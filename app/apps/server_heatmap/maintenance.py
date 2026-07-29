from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.auditlog.models import ActionRateLimit, OperationalAlert

from .models import (
    InventoryJob,
    InventoryObservation,
    InventorySyncRun,
    ServerInventoryConfiguration,
)


TERMINAL_JOB_STATUSES = (
    InventoryJob.STATUS_COMPLETED,
    InventoryJob.STATUS_FAILED,
    InventoryJob.STATUS_CANCELLED,
)


def _old_inventory_runs(cutoff):
    protected_ids = set()
    for source in (
        InventorySyncRun.SOURCE_AD,
        InventorySyncRun.SOURCE_SIEM,
        InventorySyncRun.SOURCE_LEGACY,
    ):
        latest_id = (
            InventorySyncRun.objects.filter(source=source)
            .order_by("-started_at", "-id")
            .values_list("id", flat=True)
            .first()
        )
        if latest_id:
            protected_ids.add(latest_id)
    return InventorySyncRun.objects.filter(
        started_at__lt=cutoff,
    ).exclude(id__in=protected_ids)


def maintain_server_inventory(
    *,
    dry_run=True,
    now=None,
    inventory_days=None,
    job_days=None,
    resolved_alert_days=None,
    rate_limit_days=None,
):
    now = now or timezone.now()
    configuration = ServerInventoryConfiguration.load()
    inventory_days = (
        configuration.inventory_history_days
        if inventory_days is None
        else max(0, int(inventory_days))
    )
    job_days = (
        configuration.job_history_days
        if job_days is None
        else max(0, int(job_days))
    )
    resolved_alert_days = (
        settings.OPS_RESOLVED_ALERT_RETENTION_DAYS
        if resolved_alert_days is None
        else max(0, int(resolved_alert_days))
    )
    rate_limit_days = (
        settings.ADMIN_RATE_LIMIT_RETENTION_DAYS
        if rate_limit_days is None
        else max(0, int(rate_limit_days))
    )

    run_queryset = InventorySyncRun.objects.none()
    if inventory_days:
        run_queryset = _old_inventory_runs(now - timedelta(days=inventory_days))

    job_queryset = InventoryJob.objects.none()
    if job_days:
        job_queryset = InventoryJob.objects.filter(
            status__in=TERMINAL_JOB_STATUSES,
            finished_at__lt=now - timedelta(days=job_days),
        )

    alert_queryset = OperationalAlert.objects.none()
    if resolved_alert_days:
        alert_queryset = OperationalAlert.objects.filter(
            status=OperationalAlert.STATUS_RESOLVED,
            resolved_at__lt=now - timedelta(days=resolved_alert_days),
        )

    rate_limit_queryset = ActionRateLimit.objects.none()
    if rate_limit_days:
        rate_limit_queryset = ActionRateLimit.objects.filter(
            last_request_at__lt=now - timedelta(days=rate_limit_days),
        )

    result = {
        "dry_run": bool(dry_run),
        "inventory_runs": run_queryset.count(),
        "inventory_observations": InventoryObservation.objects.filter(
            sync_run__in=run_queryset,
        ).count(),
        "inventory_jobs": job_queryset.count(),
        "resolved_alerts": alert_queryset.count(),
        "rate_limit_rows": rate_limit_queryset.count(),
    }
    if dry_run:
        return result

    with transaction.atomic():
        run_queryset.delete()
        job_queryset.delete()
        alert_queryset.delete()
        rate_limit_queryset.delete()
    return result
