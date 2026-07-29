import json
import logging
from contextvars import ContextVar
from datetime import datetime, timezone


request_id_context = ContextVar("request_id", default="")
actor_id_context = ContextVar("actor_id", default=None)


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = getattr(record, "request_id", "") or request_id_context.get()
        return True


class JsonFormatter(logging.Formatter):
    extra_fields = (
        "request_id",
        "event",
        "alert_code",
        "job_id",
        "batch_id",
        "sync_run_id",
        "source",
        "duration_seconds",
        "metrics",
    )

    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in self.extra_fields:
            value = getattr(record, field, None)
            if value not in (None, ""):
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)
