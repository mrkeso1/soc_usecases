import logging

from django.conf import settings
from django.utils import timezone

from apps.auditlog.alerts import safe_emit_operational_alert, safe_resolve_operational_alert

from .inventory_filters import apply_inventory_filters
from .management.commands.sync_server_inventory import build_ad_connector, build_siem_connector
from .models import InventorySyncRun, ServerAsset
from .network_diagnostics import diagnose_ingestion_gaps
from .reconciliation import reprocess_stored_inventory, synchronize_inventory


logger = logging.getLogger("soc.inventory")


def _progress(callback, stage, **details):
    if callback:
        callback(stage, details)


def run_full_inventory_sync(*, siem_file=None, progress_callback=None):
    _progress(progress_callback, "collect_ad")
    ad_run = synchronize_inventory(
        InventorySyncRun.SOURCE_AD,
        build_ad_connector(),
        metadata={"full_sync": True},
        apply_filters_after=False,
    )
    _progress(progress_callback, "collect_siem", ad_run_id=ad_run.id)
    siem_run = synchronize_inventory(
        InventorySyncRun.SOURCE_SIEM,
        build_siem_connector(path=siem_file),
        metadata={"full_sync": True},
        apply_filters_after=False,
    )
    _progress(
        progress_callback,
        "apply_filters",
        ad_run_id=ad_run.id,
        siem_run_id=siem_run.id,
    )
    filters_result = apply_inventory_filters()
    _progress(progress_callback, "calculate_metrics")

    total_ad = ServerAsset.objects.filter(
        is_enabled=True,
        is_excluded_by_rule=False,
        in_active_directory=True,
    ).count()
    covered = ServerAsset.objects.filter(
        is_enabled=True,
        is_excluded_by_rule=False,
        in_active_directory=True,
        in_siem=True,
    ).count()
    coverage = round(covered / total_ad * 100, 1) if total_ad else 0.0
    previous = (
        InventorySyncRun.objects.filter(
            source=InventorySyncRun.SOURCE_SIEM,
            status=InventorySyncRun.STATUS_SUCCESS,
        )
        .exclude(pk=siem_run.pk)
        .first()
    )
    previous_coverage = (
        (previous.metadata or {}).get("published_coverage_percent")
        if previous
        else None
    )
    siem_run.metadata = {
        **(siem_run.metadata or {}),
        "published_at": timezone.now().isoformat(),
        "published_total_ad": total_ad,
        "published_covered": covered,
        "published_coverage_percent": coverage,
    }
    siem_run.save(update_fields=["metadata"])

    if previous_coverage is not None:
        drop = round(float(previous_coverage) - coverage, 1)
        if drop >= settings.OPS_COVERAGE_DROP_THRESHOLD:
            safe_emit_operational_alert(
                code="inventory_coverage_drop",
                fingerprint="inventory_coverage_drop",
                title="Caída brusca de cobertura SIEM",
                message=(
                    f"La cobertura bajó de {previous_coverage}% a {coverage}% "
                    f"({drop} puntos)."
                ),
                context={
                    "previous_sync_run_id": previous.id,
                    "sync_run_id": siem_run.id,
                    "previous_percent": previous_coverage,
                    "current_percent": coverage,
                    "drop_points": drop,
                },
            )
        else:
            safe_resolve_operational_alert("inventory_coverage_drop")

    result = {
        "ad_run_id": ad_run.id,
        "ad_records": ad_run.records_read,
        "siem_run_id": siem_run.id,
        "siem_records": siem_run.records_read,
        "filters": filters_result,
        "total_ad": total_ad,
        "covered": covered,
        "coverage_percent": coverage,
    }
    logger.info(
        "Se publicó la actualización conjunta de inventario.",
        extra={
            "event": "inventory_full_sync_published",
            "sync_run_id": siem_run.id,
            "metrics": result,
        },
    )
    _progress(progress_callback, "completed", **result)
    return result


def run_reprocess_inventory(*, progress_callback=None):
    _progress(progress_callback, "reconcile_stored_inventory")
    result = reprocess_stored_inventory()
    _progress(progress_callback, "completed", **result)
    return result


def run_apply_filters(*, progress_callback=None):
    _progress(progress_callback, "apply_filters")
    result = apply_inventory_filters()
    _progress(progress_callback, "completed", **result)
    return result


def run_network_diagnostics(*, progress_callback=None):
    _progress(progress_callback, "diagnose_network", scope="pending_or_disabled")
    result = diagnose_ingestion_gaps(
        limit=None,
        workers=16,
        timeout=2,
        only_unchecked=True,
        include_disabled=True,
        include_covered=True,
        auto_disable_unreachable=True,
    )
    _progress(progress_callback, "completed", **result)
    return result
