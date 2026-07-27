import ipaddress
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .classification import active_naming_rules, apply_automatic_classification
from .connectors.base import InventoryRecord
from .models import (
    AssetIdentifier,
    InventoryObservation,
    InventorySyncRun,
    ReconciliationIssue,
    ServerAsset,
    ServerInventoryConfiguration,
)


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


def reconcile_observation(observation, record, *, naming_rules=None):
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

    source = observation.source
    observed_at = record.observed_at or timezone.now()
    if source == InventorySyncRun.SOURCE_AD:
        asset.in_active_directory = True
        asset.ad_last_seen_at = timezone.now()
        asset.ad_last_logon_at = record.observed_at
        if record.organizational_unit:
            asset.organizational_unit = record.organizational_unit
        if record.environment:
            asset.environment = record.environment
    elif source == InventorySyncRun.SOURCE_SIEM:
        asset.in_siem = True
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
    asset.is_enabled = True
    if asset.classification_source == ServerAsset.CLASSIFICATION_AUTO:
        apply_automatic_classification(asset, save=False, rules=naming_rules)
    asset.save()

    _save_identifier(asset, AssetIdentifier.KIND_HOSTNAME, canonical_hostname, source, observed_at)
    _save_identifier(asset, AssetIdentifier.KIND_FQDN, fqdn, source, observed_at)
    _save_identifier(asset, AssetIdentifier.KIND_IP, record.ip_address, source, observed_at)
    observation.asset = asset
    observation.save(update_fields=["asset"])
    return asset, created


def synchronize_inventory(source, connector, *, metadata=None):
    run = InventorySyncRun.objects.create(source=source, metadata=metadata or {})
    try:
        collected_records = connector.collect()
        records, duplicate_count = _deduplicate_records(collected_records)
        naming_rules = active_naming_rules()
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
                    naming_rules=naming_rules,
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
            }
            if source == InventorySyncRun.SOURCE_AD:
                retention_days = ServerInventoryConfiguration.load().retention_days
                deleted_assets = 0
                if retention_days:
                    cutoff = timezone.now() - timedelta(days=retention_days)
                    stale_assets = ServerAsset.objects.filter(
                        Q(ad_last_logon_at__lt=cutoff)
                        | Q(ad_last_logon_at__isnull=True, created_at__lt=cutoff),
                    )
                    deleted_assets = stale_assets.count()
                    stale_assets.delete()
                run.metadata["deleted_stale_assets"] = deleted_assets
            run.save()
        return run
    except Exception as exc:
        run.status = InventorySyncRun.STATUS_FAILED
        run.finished_at = timezone.now()
        run.error_message = str(exc)
        run.save(update_fields=["status", "finished_at", "error_message"])
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


def reprocess_stored_inventory():
    latest_runs = []
    for source in (InventorySyncRun.SOURCE_AD, InventorySyncRun.SOURCE_SIEM):
        run = InventorySyncRun.objects.filter(
            source=source,
            status=InventorySyncRun.STATUS_SUCCESS,
        ).first()
        if run:
            latest_runs.append(run)

    naming_rules = active_naming_rules()
    processed = 0
    matched = 0
    with transaction.atomic():
        ServerAsset.objects.update(in_active_directory=False, in_siem=False)
        for run in latest_runs:
            run.issues.all().delete()
            for observation in run.observations.all().iterator(chunk_size=500):
                asset, _ = reconcile_observation(
                    observation,
                    _record_from_observation(observation),
                    naming_rules=naming_rules,
                )
                processed += 1
                matched += bool(asset)
            run.issues_count = run.issues.count()
            run.save(update_fields=["issues_count"])

        # También actualiza equipos manualmente cargados que no estén en las últimas observaciones.
        pending = ServerAsset.objects.filter(classification_source=ServerAsset.CLASSIFICATION_AUTO)
        for asset in pending.iterator(chunk_size=500):
            apply_automatic_classification(asset, rules=naming_rules)

    return {"processed": processed, "matched": matched, "runs": len(latest_runs)}
