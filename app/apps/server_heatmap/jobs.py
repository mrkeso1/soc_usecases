import logging
import socket
import threading
import uuid
from contextlib import contextmanager
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, close_old_connections, transaction
from django.db.models import F
from django.utils import timezone

from apps.auditlog.alerts import safe_emit_operational_alert, safe_resolve_operational_alert

from .inventory_operations import (
    run_apply_filters,
    run_full_inventory_sync,
    run_network_diagnostics,
    run_reprocess_inventory,
    run_siem_inventory_sync,
)
from .models import InventoryJob, ServerInventoryConfiguration


logger = logging.getLogger("soc.inventory")


def enqueue_inventory_job(
    job_type,
    *,
    requested_by=None,
    payload=None,
    idempotency_key=None,
    max_attempts=None,
):
    payload = payload or {}
    idempotency_key = (idempotency_key or uuid.uuid4().hex)[:100]
    max_attempts = max_attempts or settings.SERVER_INVENTORY_JOB_MAX_ATTEMPTS
    try:
        with transaction.atomic():
            existing_key = InventoryJob.objects.filter(
                idempotency_key=idempotency_key,
            ).first()
            if existing_key:
                return existing_key, False
            active = (
                InventoryJob.objects.select_for_update()
                .filter(job_type=job_type, status__in=InventoryJob.ACTIVE_STATUSES)
                .first()
            )
            if active:
                if active.status == InventoryJob.STATUS_RUNNING:
                    active.rerun_requested = True
                    active.save(update_fields=["rerun_requested", "updated_at"])
                return active, False
            return (
                InventoryJob.objects.create(
                    job_type=job_type,
                    idempotency_key=idempotency_key,
                    payload=payload,
                    requested_by=requested_by if getattr(requested_by, "pk", None) else None,
                    max_attempts=max_attempts,
                ),
                True,
            )
    except IntegrityError:
        existing = InventoryJob.objects.filter(
            job_type=job_type,
            status__in=InventoryJob.ACTIVE_STATUSES,
        ).first()
        if existing:
            return existing, False
        return InventoryJob.objects.get(idempotency_key=idempotency_key), False


def enqueue_due_siem_sync(*, now=None):
    now = now or timezone.now()
    ServerInventoryConfiguration.load()
    with transaction.atomic():
        configuration = ServerInventoryConfiguration.objects.select_for_update().get(pk=1)
        if not configuration.siem_sync_enabled:
            return None, False
        local_now = timezone.localtime(now)
        if local_now.time().replace(tzinfo=None) < configuration.siem_sync_time:
            return None, False
        if configuration.siem_sync_last_enqueued_at:
            last_date = timezone.localtime(
                configuration.siem_sync_last_enqueued_at,
            ).date()
            elapsed_days = (local_now.date() - last_date).days
            if elapsed_days < max(1, configuration.siem_sync_interval_days):
                return None, False
        job, created = enqueue_inventory_job(
            InventoryJob.TYPE_SIEM_SYNC,
            payload={"scheduled": True},
            idempotency_key=f"scheduled-siem:{local_now.date().isoformat()}",
        )
        configuration.siem_sync_last_enqueued_at = now
        configuration.save(update_fields=["siem_sync_last_enqueued_at", "updated_at"])
        return job, created


def recover_zombie_jobs():
    now = timezone.now()
    recovered = failed = 0
    with transaction.atomic():
        zombies = list(
            InventoryJob.objects.select_for_update(skip_locked=True).filter(
                status=InventoryJob.STATUS_RUNNING,
                lease_expires_at__lt=now,
            )
        )
        for job in zombies:
            if job.attempts >= job.max_attempts:
                job.status = InventoryJob.STATUS_FAILED
                job.finished_at = now
                failed += 1
            else:
                job.status = InventoryJob.STATUS_RETRYING
                job.available_at = now
                recovered += 1
            job.worker_id = ""
            job.heartbeat_at = None
            job.lease_expires_at = None
            job.last_error = "El worker anterior dejó de enviar heartbeat."
            job.save()
    for job in zombies:
        safe_emit_operational_alert(
            code="inventory_job_zombie",
            fingerprint=f"inventory_job_zombie:{job.job_type}",
            severity="error" if job.status == InventoryJob.STATUS_FAILED else "warning",
            title="Se recuperó un trabajo de inventario interrumpido",
            message=(
                f"El trabajo {job.id} ({job.get_job_type_display()}) perdió su lease "
                f"y quedó {job.get_status_display().lower()}."
            ),
            context={"job_id": job.id, "attempts": job.attempts, "status": job.status},
        )
    return {"recovered": recovered, "failed": failed}


def claim_next_inventory_job(worker_id):
    now = timezone.now()
    lease = timedelta(seconds=settings.SERVER_INVENTORY_JOB_LEASE_SECONDS)
    with transaction.atomic():
        job = (
            InventoryJob.objects.select_for_update(skip_locked=True)
            .filter(
                status__in=[
                    InventoryJob.STATUS_PENDING,
                    InventoryJob.STATUS_RETRYING,
                ],
                available_at__lte=now,
                attempts__lt=F("max_attempts"),
            )
            .order_by("available_at", "created_at")
            .first()
        )
        if not job:
            return None
        job.status = InventoryJob.STATUS_RUNNING
        job.attempts += 1
        job.started_at = job.started_at or now
        job.heartbeat_at = now
        job.lease_expires_at = now + lease
        job.worker_id = worker_id
        job.last_error = ""
        job.save()
        return job


def _heartbeat(job_id, worker_id):
    now = timezone.now()
    return InventoryJob.objects.filter(
        pk=job_id,
        status=InventoryJob.STATUS_RUNNING,
        worker_id=worker_id,
    ).update(
        heartbeat_at=now,
        lease_expires_at=now + timedelta(seconds=settings.SERVER_INVENTORY_JOB_LEASE_SECONDS),
    )


@contextmanager
def job_heartbeat(job_id, worker_id):
    stop = threading.Event()

    def run():
        while not stop.wait(settings.SERVER_INVENTORY_JOB_HEARTBEAT_SECONDS):
            close_old_connections()
            try:
                if not _heartbeat(job_id, worker_id):
                    break
            except Exception:
                logger.exception(
                    "Falló el heartbeat del trabajo de inventario.",
                    extra={"event": "inventory_job_heartbeat_failed", "job_id": job_id},
                )
            finally:
                close_old_connections()

    thread = threading.Thread(
        target=run,
        name=f"inventory-job-heartbeat-{job_id}",
        daemon=True,
    )
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=max(1, settings.SERVER_INVENTORY_JOB_HEARTBEAT_SECONDS + 1))


def _update_progress(job_id, worker_id, stage, details):
    InventoryJob.objects.filter(
        pk=job_id,
        status=InventoryJob.STATUS_RUNNING,
        worker_id=worker_id,
    ).update(
        progress={
            "stage": stage,
            "details": details,
            "updated_at": timezone.now().isoformat(),
        },
    )


def _execute(job, worker_id):
    callback = lambda stage, details: _update_progress(job.id, worker_id, stage, details)
    if job.job_type == InventoryJob.TYPE_FULL_SYNC:
        return run_full_inventory_sync(
            siem_file=(job.payload or {}).get("siem_file"),
            progress_callback=callback,
        )
    if job.job_type == InventoryJob.TYPE_REPROCESS:
        return run_reprocess_inventory(progress_callback=callback)
    if job.job_type == InventoryJob.TYPE_APPLY_FILTERS:
        return run_apply_filters(progress_callback=callback)
    if job.job_type == InventoryJob.TYPE_NETWORK_DIAGNOSTIC:
        return run_network_diagnostics(progress_callback=callback)
    if job.job_type == InventoryJob.TYPE_SIEM_SYNC:
        return run_siem_inventory_sync(
            siem_file=(job.payload or {}).get("siem_file"),
            scheduled=(job.payload or {}).get("scheduled", False),
            progress_callback=callback,
        )
    raise ValueError(f"Tipo de trabajo no soportado: {job.job_type}")


def execute_inventory_job(job, worker_id):
    logger.info(
        "El worker tomó un trabajo de inventario.",
        extra={"event": "inventory_job_started", "job_id": job.id},
    )
    try:
        with job_heartbeat(job.id, worker_id):
            result = _execute(job, worker_id)
    except Exception as exc:
        now = timezone.now()
        with transaction.atomic():
            current = InventoryJob.objects.select_for_update().get(pk=job.pk)
            current.last_error = str(exc)
            current.worker_id = ""
            current.heartbeat_at = None
            current.lease_expires_at = None
            if current.attempts < current.max_attempts:
                delay = min(900, 30 * (2 ** max(0, current.attempts - 1)))
                current.status = InventoryJob.STATUS_RETRYING
                current.available_at = now + timedelta(seconds=delay)
            else:
                current.status = InventoryJob.STATUS_FAILED
                current.finished_at = now
            current.save()
        logger.exception(
            "Falló un trabajo de inventario.",
            extra={"event": "inventory_job_failed", "job_id": job.id},
        )
        safe_emit_operational_alert(
            code="inventory_job_failed",
            fingerprint=f"inventory_job_failed:{job.job_type}",
            severity="error",
            title=f"Falló el trabajo {job.get_job_type_display()}",
            message=str(exc),
            context={
                "job_id": job.id,
                "attempts": current.attempts,
                "status": current.status,
            },
        )
        return current

    now = timezone.now()
    with transaction.atomic():
        current = InventoryJob.objects.select_for_update().get(pk=job.pk)
        rerun_requested = current.rerun_requested
        current.status = InventoryJob.STATUS_COMPLETED
        current.result = result or {}
        current.progress = {
            "stage": "completed",
            "details": result or {},
            "updated_at": now.isoformat(),
        }
        current.finished_at = now
        current.worker_id = ""
        current.heartbeat_at = None
        current.lease_expires_at = None
        current.rerun_requested = False
        current.save()
        if rerun_requested:
            InventoryJob.objects.create(
                job_type=current.job_type,
                idempotency_key=uuid.uuid4().hex,
                payload=current.payload,
                requested_by=current.requested_by,
                max_attempts=current.max_attempts,
            )
    safe_resolve_operational_alert(f"inventory_job_failed:{job.job_type}")
    safe_resolve_operational_alert(f"inventory_job_zombie:{job.job_type}")
    logger.info(
        "Finalizó un trabajo de inventario.",
        extra={
            "event": "inventory_job_completed",
            "job_id": job.id,
            "metrics": result or {},
        },
    )
    return current


def default_worker_id():
    return f"{socket.gethostname()}:{uuid.uuid4().hex[:8]}"
