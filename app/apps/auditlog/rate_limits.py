import logging
import math
from dataclasses import dataclass
from datetime import timedelta
from functools import wraps

from django.conf import settings
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone

from .models import ActionRateLimit


logger = logging.getLogger("soc.ops")


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int
    remaining: int


def consume_action_rate_limit(*, user, scope, limit, window_seconds):
    if not getattr(user, "is_authenticated", False):
        raise ValueError("El rate limit requiere un usuario autenticado.")
    limit = max(1, int(limit))
    window_seconds = max(1, int(window_seconds))
    now = timezone.now()
    with transaction.atomic():
        state, created = (
            ActionRateLimit.objects.select_for_update()
            .get_or_create(
                user=user,
                scope=scope,
                defaults={
                    "window_started_at": now,
                    "last_request_at": now,
                    "request_count": 1,
                },
            )
        )
        if created:
            return RateLimitResult(True, 0, limit - 1)

        elapsed = (now - state.window_started_at).total_seconds()
        if elapsed >= window_seconds:
            state.window_started_at = now
            state.request_count = 1
            state.blocked_count = 0
            state.last_request_at = now
            state.save()
            return RateLimitResult(True, 0, limit - 1)

        state.last_request_at = now
        if state.request_count >= limit:
            state.blocked_count += 1
            state.save(update_fields=["blocked_count", "last_request_at", "updated_at"])
            return RateLimitResult(
                False,
                max(1, math.ceil(window_seconds - elapsed)),
                0,
            )

        state.request_count += 1
        state.save(update_fields=["request_count", "last_request_at", "updated_at"])
        return RateLimitResult(True, 0, limit - state.request_count)


def database_rate_limit(*, scope, limit_setting, default_limit, methods=("POST",)):
    protected_methods = {method.upper() for method in methods}

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(request, *args, **kwargs):
            if request.method.upper() not in protected_methods:
                return view_func(request, *args, **kwargs)

            result = consume_action_rate_limit(
                user=request.user,
                scope=scope,
                limit=getattr(settings, limit_setting, default_limit),
                window_seconds=settings.ADMIN_ACTION_RATE_LIMIT_WINDOW_SECONDS,
            )
            if result.allowed:
                return view_func(request, *args, **kwargs)

            logger.warning(
                "Se bloqueó una acción administrativa por exceso de solicitudes.",
                extra={
                    "event": "admin_action_rate_limited",
                    "metrics": {
                        "user_id": request.user.pk,
                        "scope": scope,
                        "retry_after": result.retry_after,
                    },
                },
            )
            if "application/json" in request.headers.get("Accept", ""):
                response = JsonResponse(
                    {
                        "detail": "Demasiadas solicitudes. Intentá nuevamente más tarde.",
                        "retry_after": result.retry_after,
                    },
                    status=429,
                )
            else:
                response = render(
                    request,
                    "errors/rate_limited.html",
                    {"retry_after": result.retry_after},
                    status=429,
                )
            response["Retry-After"] = str(result.retry_after)
            return response

        return wrapped

    return decorator
