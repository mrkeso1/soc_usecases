import ipaddress
import ipaddress
import logging
import time
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .classification import active_classification_rules, apply_automatic_classification
from .connectors.base import InventoryRecord
from .inventory_filters import apply_inventory_filters
from .models import (
    AssetIdentifier,
    InventoryObservation,
    InventorySyncRun,
    ReconciliationIssue,
    ServerAsset,
    ServerInventoryConfiguration,
)
from .network_diagnostics import resolve_observation_identity
from apps.auditlog.alerts import safe_emit_operational_alert, safe_resolve_operational_alert


logger = logging.getLogger("soc.inventory")


def normalize_hostname(value):
    return (value or "").strip().lower().rstrip(".").split(".", 1)[0]


def normalize_fqdn(value):
    return (value or "").strip().lower().rstrip(".")


def normalize_ip(value):
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def normalize_external_id(value):
    return (value or "").strip().lower().rstrip(".")


def _record_quality(record):
    return sum(
        bool(value)
        for value in (
            record.hostname,
            record.fqdn,
            record.ip_address,
            record.os_name,
            record.organizational_unit,
            record.environment,
            record.groups,
            record.server_type_hint,
            record.observed_at,
        )
    )


def _deduplicate_records(records):
    unique_records = {}
    duplicate_count = 0
    for position, record in enumerate(records):
        external_id = normalize_external_id(record.external_id)
        key = external_id or f"__missing_external_id_{position}"
        existing = unique_records.get(key)
        if existing is None:
            unique_records[key] = record
            continue
        duplicate_count += 1
        if _record_quality(record) > _record_quality(existing):
            unique_records[key] = record
    return list(unique_records.values()), duplicate_count


def os_family_from_name(value):
    normalized = (value or "").lower()
    if "windows" in normalized:
        return ServerAsset.OS_WINDOWS
    if any(token in normalized for token in ("linux", "sles", "red hat", "ubuntu", "debian", "centos")):
        return ServerAsset.OS_LINUX
    if any(token in normalized for token in ("aix", "unix", "solaris")):
        return ServerAsset.OS_UNIX
    return ServerAsset.OS_UNKNOWN


def _candidate_assets(record):
    identifiers = []
    hostname = normalize_hostname(record.hostname or record.fqdn)
    fqdn = normalize_fqdn(record.fqdn)
    ip = normalize_ip(record.ip_address)
    if hostname:
        identifiers.append((AssetIdentifier.KIND_HOSTNAME, hostname))
    if fqdn and "." in fqdn:
        identifiers.append((AssetIdentifier.KIND_FQDN, fqdn))

    asset_ids = set()
    for kind, value in identifiers:
        asset_ids.update(
            AssetIdentifier.objects.filter(kind=kind, normalized_value=value)
            .values_list("asset_id", flat=True)
        )
    if hostname:
        asset_ids.update(
            ServerAsset.objects.filter(hostname__iexact=hostname).values_list("id", flat=True)
        )

    # La IP se usa solo como respaldo y únicamente si identifica un equipo.
    if not asset_ids and ip:
        ip_candidates = set(
            AssetIdentifier.objects.filter(
                kind=AssetIdentifier.KIND_IP,
                normalized_value=ip,
            ).values_list("asset_id", flat=True)
        )
        ip_candidates.update(
            ServerAsset.objects.filter(ip_address=ip).values_list("id", flat=True)
        )
        if len(ip_candidates) == 1:
            asset_ids = ip_candidates
    return ServerAsset.objects.filter(id__in=asset_ids)


def _save_identifier(asset, kind, value, source, seen_at):
    normalized = {
        AssetIdentifier.KIND_HOSTNAME: normalize_hostname,
        AssetIdentifier.KIND_FQDN: normalize_fqdn,
        AssetIdentifier.KIND_IP: normalize_ip,
    }[kind](value)
    if not normalized:
        return
    AssetIdentifier.objects.update_or_create(
        asset=asset,
        kind=kind,
        normalized_value=normalized,
        source=source,
        defaults={"value": value, "last_seen_at": seen_at},
    )


def reconcile_observation(observation, record, *, classification_rules=None):
    candidates = list(_candidate_assets(record)[:2])
    canonical_hostname = normalize_hostname(record.hostname or record.fqdn)
    if len(candidates) > 1:
        ReconciliationIssue.objects.create(
            sync_run=observation.sync_run,
            observation=observation,
            issue_type=ReconciliationIssue.TYPE_AMBIGUOUS,
            identifier=canonical_hostname or normalize_ip(record.ip_address),
            details={"candidate_ids": [asset.id for asset in candidates]},
        )
        return None, False
    if candidates:
        asset = candidates[0]
        created = False
    elif observation.source == InventorySyncRun.SOURCE_SIEM:
        ReconciliationIssue.objects.create(
            sync_run=observation.sync_run,
            observation=observation,
            issue_type=ReconciliationIssue.TYPE_NOT_IN_AD,
            identifier=canonical_hostname or normalize_ip(record.ip_address) or record.external_id,
            details={"reason": "El registro SIEM no coincide con ningún equipo del inventario AD."},
        )
        return None, False
    elif canonical_hostname:
        asset = ServerAsset.objects.create(
            hostname=canonical_hostname,
            display_name=record.hostname or canonical_hostname,
        )
        created = True
    else:
        ReconciliationIssue.objects.create(
            sync_run=observation.sync_run,
            observation=observation,
            issue_type=ReconciliationIssue.TYPE_MISSING_IDENTIFIER,
            identifier=record.external_id,
            details={"reason": "No se recibió hostname y la IP no coincide con un equipo conocido."},
        )
        return None, False

    manual_classification = (
        asset.classification_source == ServerAsset.CLASSIFICATION_MANUAL
    )
    manual_values = {
        "category_id": asset.category_id,
        "os_family": asset.os_family,
        "server_type": asset.server_type,
        "application_name": asset.application_name,
        "environment": asset.environment,
    }
    source = observation.source
    observed_at = record.observed_at or timezone.now()
    if source == InventorySyncRun.SOURCE_AD:
        asset.in_active_directory = True
        # Una excepción Solo SIEM vuelve al flujo normal apenas AD la observa.
        # Se conserva quién/cuándo la aprobó como historial, pero deja de ser excepción.
        asset.is_siem_only_approved = False
        # Los equipos deshabilitados por cargas heredadas vuelven a entrar en
        # alcance al reaparecer en AD. Una baja manual auditada siempre se respeta.
        if not asset.is_enabled and not asset.disable_events.exists():
            asset.is_enabled = True
        asset.ad_last_seen_at = timezone.now()
        if asset.ad_first_seen_at is None:
            asset.ad_first_seen_at = observation.created_at or timezone.now()
        asset.ad_last_logon_at = record.observed_at
        if record.organizational_unit:
            asset.organizational_unit = record.organizational_unit
        if record.environment:
            asset.environment = record.environment
    elif source == InventorySyncRun.SOURCE_SIEM:
        asset.in_siem = True
        if asset.siem_first_seen_at is None:
            asset.siem_first_seen_at = observation.created_at or timezone.now()
        asset.siem_last_seen_at = observed_at
        if record.groups:
            asset.siem_groups = record.groups

    fqdn = normalize_fqdn(record.fqdn)
    if fqdn and "." in fqdn:
        asset.domain = fqdn.split(".", 1)[1]
    if record.ip_address:
        asset.ip_address = normalize_ip(record.ip_address) or asset.ip_address
    if record.os_name:
        asset.os_name = record.os_name
        if asset.classification_source == ServerAsset.CLASSIFICATION_AUTO:
            asset.os_family = os_family_from_name(record.os_name)
    asset.inventory_source = source
    if asset.classification_source == ServerAsset.CLASSIFICATION_AUTO:
        apply_automatic_classification(asset, save=False, rules=classification_rules)
    if manual_classification:
        # Defensa adicional: aunque se agregue una nueva fuente automática en
        # el futuro, los valores elegidos por una persona conservan prioridad 1.
        for field, value in manual_values.items():
            setattr(asset, field, value)
        asset.classification_source = ServerAsset.CLASSIFICATION_MANUAL
    asset.save()

    _save_identifier(asset, AssetIdentifier.KIND_HOSTNAME, canonical_hostname, source, observed_at)
    _save_identifier(asset, AssetIdentifier.KIND_FQDN, fqdn, source, observed_at)
    _save_identifier(asset, AssetIdentifier.KIND_IP, record.ip_address, source, observed_at)
    observation.asset = asset
    observation.save(update_fields=["asset"])
    return asset, created


def synchronize_inventory(source, connector, *, metadata=None, apply_filters_after=True):
    run = InventorySyncRun.objects.create(source=source, metadata=metadata or {})
    started = time.monotonic()
    logger.info(
        "Comenzó la sincronización de inventario.",
        extra={
            "event": "inventory_sync_started",
            "sync_run_id": run.id,
            "source": source,
        },
    )
    try:
        collected_records = connector.collect()
        records, duplicate_count = _deduplicate_records(collected_records)
        dns_attempted = sum(
            bool((record.raw_data or {}).get("dns_resolution_attempted"))
            for record in records
        )
        dns_resolved = sum(
            bool((record.raw_data or {}).get("resolved_hostname"))
            for record in records
        )
        classification_rules = active_classification_rules()
        with transaction.atomic():
            if source == InventorySyncRun.SOURCE_AD:
                ServerAsset.objects.update(in_active_directory=False)
            elif source == InventorySyncRun.SOURCE_SIEM:
                ServerAsset.objects.update(in_siem=False)

            created_ids = set()
            updated_ids = set()
            for record in records:
                observation = InventoryObservation.objects.create(
                    sync_run=run,
                    source=source,
                    external_id=normalize_external_id(record.external_id),
                    hostname=record.hostname,
                    fqdn=record.fqdn,
                    ip_address=normalize_ip(record.ip_address) or None,
                    os_name=record.os_name,
                    organizational_unit=record.organizational_unit,
                    environment=record.environment,
                    groups=record.groups,
                    server_type_hint=record.server_type_hint,
                    observed_at=record.observed_at,
                    raw_data=record.raw_data,
                )
                asset, was_created = reconcile_observation(
                    observation,
                    record,
                    classification_rules=classification_rules,
                )
                if asset and was_created:
                    created_ids.add(asset.id)
                elif asset:
                    updated_ids.add(asset.id)

            run.status = InventorySyncRun.STATUS_SUCCESS
            run.finished_at = timezone.now()
            run.records_read = len(collected_records)
            run.assets_created = len(created_ids)
            run.assets_updated = len(updated_ids)
            run.issues_count = run.issues.count()
            run.metadata = {
                **run.metadata,
                "unique_records": len(records),
                "duplicate_records": duplicate_count,
                "dns_resolution_attempted": dns_attempted,
                "dns_resolution_resolved": dns_resolved,
            }
            if source == InventorySyncRun.SOURCE_AD:
                retention_days = ServerInventoryConfiguration.load().retention_days
                deleted_assets = 0
                if retention_days:
                    cutoff = timezone.now() - timedelta(days=retention_days)
                    stale_assets = ServerAsset.objects.filter(
                        in_active_directory=False,
                        is_siem_only_approved=False,
                    ).filter(
                        Q(ad_last_logon_at__lt=cutoff)
                        | Q(ad_last_logon_at__isnull=True, created_at__lt=cutoff),
                    )
                    deleted_assets = stale_assets.count()
                    stale_assets.delete()
                run.metadata["deleted_stale_assets"] = deleted_assets
            run.save()
        if apply_filters_after:
            apply_inventory_filters()
        duration = round(time.monotonic() - started, 3)
        metrics = {
            "records_read": run.records_read,
            "assets_created": run.assets_created,
            "assets_updated": run.assets_updated,
            "issues_count": run.issues_count,
            "dns_attempted": dns_attempted,
            "dns_resolved": dns_resolved,
        }
        logger.info(
            "Finalizó la sincronización de inventario.",
            extra={
                "event": "inventory_sync_succeeded",
                "sync_run_id": run.id,
                "source": source,
                "duration_seconds": duration,
                "metrics": metrics,
            },
        )
        safe_resolve_operational_alert(f"inventory_sync_failed:{source}")
        if source == InventorySyncRun.SOURCE_SIEM and dns_attempted:
            dns_failed_percent = round((dns_attempted - dns_resolved) / dns_attempted * 100, 1)
            fingerprint = "inventory_dns_linux_failure"
            if dns_failed_percent >= settings.OPS_DNS_FAILURE_THRESHOLD:
                safe_emit_operational_alert(
                    code="inventory_dns_linux_failure",
                    fingerprint=fingerprint,
                    title="Falló la resolución DNS de equipos Linux",
                    message=(
                        f"El {dns_failed_percent}% de las IP Linux no pudo resolver hostname."
                    ),
                    context={
                        "sync_run_id": run.id,
                        "attempted": dns_attempted,
                        "resolved": dns_resolved,
                        "failed_percent": dns_failed_percent,
                    },
                )
            else:
                safe_resolve_operational_alert(fingerprint)
        return run
    except Exception as exc:
        run.status = InventorySyncRun.STATUS_FAILED
        run.finished_at = timezone.now()
        run.error_message = str(exc)
        run.save(update_fields=["status", "finished_at", "error_message"])
        duration = round(time.monotonic() - started, 3)
        logger.exception(
            "Falló la sincronización de inventario.",
            extra={
                "event": "inventory_sync_failed",
                "sync_run_id": run.id,
                "source": source,
                "duration_seconds": duration,
            },
        )
        safe_emit_operational_alert(
            code="inventory_sync_failed",
            fingerprint=f"inventory_sync_failed:{source}",
            severity="error",
            title=f"Falló la sincronización {run.get_source_display()}",
            message=str(exc),
            context={
                "sync_run_id": run.id,
                "source": source,
                "duration_seconds": duration,
            },
        )
        raise


def _record_from_observation(observation):
    return InventoryRecord(
        external_id=observation.external_id,
        hostname=observation.hostname,
        fqdn=observation.fqdn,
        ip_address=observation.ip_address,
        os_name=observation.os_name,
        organizational_unit=observation.organizational_unit,
        environment=observation.environment,
        groups=observation.groups,
        server_type_hint=observation.server_type_hint,
        observed_at=observation.observed_at,
        raw_data=observation.raw_data,
    )


def resolve_issue_observation_identity(issue):
    """Resuelve y persiste la identidad de una observación, exista o no en AD."""
    observation = issue.observation
    if observation is None:
        raise ValidationError("El conflicto no tiene una observación asociada.")

    resolution = resolve_observation_identity(observation)
    details = dict(issue.details or {})
    details["name_resolution"] = {
        "hostname": resolution.hostname,
        "fqdn": resolution.fqdn,
        "ip_address": resolution.ip_address,
        "error": resolution.error,
        "attempted_at": timezone.now().isoformat(),
    }
    if resolution.error:
        issue.details = details
        issue.save(update_fields=["details"])
        return resolution

    observation.hostname = resolution.hostname or observation.hostname
    observation.fqdn = resolution.fqdn or observation.fqdn
    observation.ip_address = resolution.ip_address or observation.ip_address
    observation.save(update_fields=["hostname", "fqdn", "ip_address"])
    issue.details = details
    issue.save(update_fields=["details"])
    return resolution


def retry_issue_name_resolution(issue):
    """Resuelve la identidad por DNS y reintenta la conciliación con AD."""
    try:
        resolution = resolve_issue_observation_identity(issue)
    except ValidationError as exc:
        return False, "; ".join(exc.messages)
    if resolution.error:
        return False, resolution.error

    observation = issue.observation
    details = dict(issue.details or {})
    record = _record_from_observation(observation)
    candidates = list(_candidate_assets(record)[:2])
    if len(candidates) != 1:
        message = "El nombre resuelto no coincide con un único equipo de Active Directory."
        details["name_resolution"]["error"] = message
        details["name_resolution"]["candidate_ids"] = [asset.id for asset in candidates]
        issue.details = details
        issue.save(update_fields=["details"])
        return False, message

    asset, _ = reconcile_observation(
        observation,
        record,
        classification_rules=active_classification_rules(),
    )
    if not asset:
        return False, "No se pudo asociar el equipo después de resolver el nombre."
    observation.issues.filter(is_resolved=False).update(is_resolved=True)
    return True, asset.hostname


@transaction.atomic
def promote_siem_only_issue(issue, cleaned_data, *, approved_by):
    """Incorpora manualmente al inventario un registro SIEM que no existe en AD."""
    issue = ReconciliationIssue.objects.select_for_update().get(pk=issue.pk)
    observation = issue.observation
    if issue.is_resolved:
        raise ValidationError("El conflicto ya fue resuelto.")
    if issue.issue_type != ReconciliationIssue.TYPE_NOT_IN_AD:
        raise ValidationError("Sólo se pueden incorporar conflictos no encontrados en AD.")
    if observation is None or observation.source != InventorySyncRun.SOURCE_SIEM:
        raise ValidationError("La excepción debe originarse en una observación SIEM.")

    hostname = normalize_hostname(cleaned_data.get("hostname"))
    if not hostname:
        raise ValidationError("Ingresá un hostname válido.")
    ip_address = normalize_ip(cleaned_data.get("ip_address")) or None
    observation.hostname = hostname
    observation.ip_address = ip_address or observation.ip_address
    observation.save(update_fields=["hostname", "ip_address"])
    record = _record_from_observation(observation)
    candidates = list(_candidate_assets(record).select_for_update()[:2])
    if len(candidates) > 1:
        raise ValidationError("El hostname o la IP coinciden con más de un equipo existente.")
    if candidates and candidates[0].in_active_directory:
        raise ValidationError(
            "El equipo ya coincide con Active Directory; reintentá la conciliación en lugar de aprobar una excepción."
        )

    if candidates:
        asset = candidates[0]
    else:
        asset = ServerAsset(hostname=hostname)

    now = timezone.now()
    observed_at = observation.observed_at or observation.created_at or now
    asset.hostname = hostname
    asset.display_name = (cleaned_data.get("display_name") or hostname).strip()
    asset.ip_address = ip_address or observation.ip_address
    asset.os_family = cleaned_data.get("os_family") or os_family_from_name(observation.os_name)
    asset.os_name = observation.os_name or asset.os_name
    asset.category = cleaned_data.get("category")
    asset.application_name = (cleaned_data.get("application_name") or "").strip()
    asset.environment = (cleaned_data.get("environment") or observation.environment or "").strip()
    asset.is_critical = bool(cleaned_data.get("is_critical"))
    asset.is_enabled = bool(cleaned_data.get("is_enabled"))
    asset.notes = (cleaned_data.get("notes") or "").strip()
    asset.classification_source = ServerAsset.CLASSIFICATION_MANUAL
    asset.inventory_source = InventorySyncRun.SOURCE_SIEM
    asset.in_active_directory = False
    asset.in_siem = True
    asset.is_siem_only_approved = True
    asset.siem_exception_approved_at = now
    asset.siem_exception_approved_by = approved_by
    asset.siem_exception_observation = observation
    asset.siem_exception_reason = cleaned_data["approval_reason"].strip()
    asset.siem_first_seen_at = asset.siem_first_seen_at or observation.created_at or now
    asset.siem_last_seen_at = observed_at
    asset.siem_groups = observation.groups or asset.siem_groups
    fqdn = normalize_fqdn(observation.fqdn)
    if fqdn and "." in fqdn:
        asset.domain = fqdn.split(".", 1)[1]
    asset.save()

    _save_identifier(
        asset,
        AssetIdentifier.KIND_HOSTNAME,
        hostname,
        InventorySyncRun.SOURCE_SIEM,
        observed_at,
    )
    _save_identifier(
        asset,
        AssetIdentifier.KIND_FQDN,
        fqdn,
        InventorySyncRun.SOURCE_SIEM,
        observed_at,
    )
    _save_identifier(
        asset,
        AssetIdentifier.KIND_IP,
        asset.ip_address,
        InventorySyncRun.SOURCE_SIEM,
        observed_at,
    )
    observation.asset = asset
    observation.save(update_fields=["asset"])
    details = dict(issue.details or {})
    details["manual_siem_approval"] = {
        "asset_id": asset.id,
        "approved_by_id": getattr(approved_by, "pk", None),
        "approved_at": now.isoformat(),
        "reason": asset.siem_exception_reason,
    }
    observation.issues.filter(is_resolved=False).update(is_resolved=True)
    issue.details = details
    issue.is_resolved = True
    issue.save(update_fields=["details", "is_resolved"])
    return asset


def reprocess_stored_inventory():
    latest_runs = []
    ad_run = InventorySyncRun.objects.filter(
        source=InventorySyncRun.SOURCE_AD,
        status=InventorySyncRun.STATUS_SUCCESS,
    ).first()
    if not ad_run:
        ad_run = InventorySyncRun.objects.filter(
            source=InventorySyncRun.SOURCE_LEGACY,
            status=InventorySyncRun.STATUS_SUCCESS,
        ).first()
    if ad_run:
        latest_runs.append(ad_run)
    for source in (InventorySyncRun.SOURCE_SIEM,):
        run = InventorySyncRun.objects.filter(
            source=source,
            status=InventorySyncRun.STATUS_SUCCESS,
        ).first()
        if run:
            latest_runs.append(run)

    classification_rules = active_classification_rules()
    processed = 0
    matched = 0
    with transaction.atomic():
        ServerAsset.objects.update(in_active_directory=False, in_siem=False)
        for run in latest_runs:
            run.issues.all().delete()
            for observation in run.observations.all().iterator(chunk_size=500):
                if run.source == InventorySyncRun.SOURCE_LEGACY:
                    asset = observation.asset
                    if asset:
                        raw = observation.raw_data or {}
                        ingested = str(raw.get("ingestado", "")).strip().lower()
                        asset.in_active_directory = True
                        asset.in_siem = ingested in {"1", "true", "si", "sí", "yes"}
                        asset.save(update_fields=[
                            "in_active_directory",
                            "in_siem",
                            "updated_at",
                        ])
                        processed += 1
                        matched += 1
                    continue
                asset, _ = reconcile_observation(
                    observation,
                    _record_from_observation(observation),
                    classification_rules=classification_rules,
                )
                processed += 1
                matched += bool(asset)
            run.issues_count = run.issues.count()
            run.save(update_fields=["issues_count"])

        # También actualiza equipos manualmente cargados que no estén en las últimas observaciones.
        pending = ServerAsset.objects.all()
        for asset in pending.iterator(chunk_size=500):
            apply_automatic_classification(
                asset,
                rules=classification_rules,
            )

    return {"processed": processed, "matched": matched, "runs": len(latest_runs)}
