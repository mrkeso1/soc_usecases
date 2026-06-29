from .service import audit


SENSITIVE_FIELD_HINTS = ("password", "token", "secret", "csrf", "key")


def _safe_post_keys(request):
    if not hasattr(request, "POST"):
        return []
    keys = []
    for key in request.POST.keys():
        lowered = key.lower()
        if any(hint in lowered for hint in SENSITIVE_FIELD_HINTS):
            continue
        keys.append(key)
    return sorted(keys)[:50]


class AuditRequestMiddleware:
    """Write a coarse audit event for successful mutating web requests."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and response.status_code < 400
            and not getattr(request, "_soc_audit_written", False)
            and getattr(request, "user", None)
            and request.user.is_authenticated
        ):
            audit(
                request,
                "web_action",
                "request",
                request.path,
                {
                    "method": request.method,
                    "path": request.path,
                    "view_name": getattr(getattr(request, "resolver_match", None), "view_name", ""),
                    "status_code": response.status_code,
                    "content_type": response.get("Content-Type", ""),
                    "submitted_fields": _safe_post_keys(request),
                },
            )
        return response
