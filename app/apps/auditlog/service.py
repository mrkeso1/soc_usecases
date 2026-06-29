from django.conf import settings

from .models import AuditLog


def client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "") if getattr(settings, "USE_X_FORWARDED_FOR", False) else ""
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def audit(request, action, entity_type="", entity_id="", details=None, actor=None):
    user = actor if actor is not None else getattr(request, "user", None)
    if not getattr(user, "is_authenticated", False):
        user = None
    if request is not None:
        request._soc_audit_written = True
    return AuditLog.objects.create(
        actor=user,
        action=action,
        entity_type=entity_type or "",
        entity_id=str(entity_id) if entity_id not in (None, "") else "",
        ip_address=client_ip(request) if request is not None else "",
        user_agent=(request.META.get("HTTP_USER_AGENT", "") if request is not None else "")[:500],
        details=details or {},
    )
