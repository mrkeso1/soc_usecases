import logging

from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from .models import OperationalAlert


logger = logging.getLogger("soc.ops")


def _log_level(severity):
    return {
        OperationalAlert.SEVERITY_INFO: logging.INFO,
        OperationalAlert.SEVERITY_WARNING: logging.WARNING,
        OperationalAlert.SEVERITY_ERROR: logging.ERROR,
        OperationalAlert.SEVERITY_CRITICAL: logging.CRITICAL,
    }.get(severity, logging.WARNING)


def emit_operational_alert(
    *,
    code,
    title,
    message,
    severity=OperationalAlert.SEVERITY_WARNING,
    context=None,
    fingerprint="",
):
    fingerprint = (fingerprint or code)[:255]
    now = timezone.now()
    context = context or {}
    try:
        with transaction.atomic():
            alert = (
                OperationalAlert.objects.select_for_update()
                .filter(
                    fingerprint=fingerprint,
                    status__in=[
                        OperationalAlert.STATUS_OPEN,
                        OperationalAlert.STATUS_ACKNOWLEDGED,
                    ],
                )
                .first()
            )
            if alert:
                OperationalAlert.objects.filter(pk=alert.pk).update(
                    occurrences=F("occurrences") + 1,
                    last_seen_at=now,
                    severity=severity,
                    title=title,
                    message=message,
                    context=context,
                )
                alert.refresh_from_db()
            else:
                alert = OperationalAlert.objects.create(
                    code=code,
                    fingerprint=fingerprint,
                    severity=severity,
                    title=title,
                    message=message,
                    context=context,
                )
    except IntegrityError:
        alert = OperationalAlert.objects.get(
            fingerprint=fingerprint,
            status__in=[
                OperationalAlert.STATUS_OPEN,
                OperationalAlert.STATUS_ACKNOWLEDGED,
            ],
        )

    logger.log(
        _log_level(severity),
        message,
        extra={
            "event": "operational_alert",
            "alert_code": code,
            "metrics": context,
        },
    )

    return alert


def safe_emit_operational_alert(**kwargs):
    try:
        return emit_operational_alert(**kwargs)
    except Exception:
        logger.exception(
            "No se pudo persistir una alerta operativa.",
            extra={
                "event": "alert_persistence_failed",
                "alert_code": kwargs.get("code", ""),
            },
        )
        return None


def resolve_operational_alert(fingerprint):
    return OperationalAlert.objects.filter(
        fingerprint=fingerprint,
        status__in=[
            OperationalAlert.STATUS_OPEN,
            OperationalAlert.STATUS_ACKNOWLEDGED,
        ],
    ).update(
        status=OperationalAlert.STATUS_RESOLVED,
        resolved_at=timezone.now(),
    )


def safe_resolve_operational_alert(fingerprint):
    try:
        return resolve_operational_alert(fingerprint)
    except Exception:
        logger.exception(
            "No se pudo resolver una alerta operativa.",
            extra={
                "event": "alert_resolution_failed",
                "alert_code": fingerprint,
            },
        )
        return 0
