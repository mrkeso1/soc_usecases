import logging

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver


logger = logging.getLogger("soc.auth")


def _client_ip(request):
    if not request:
        return ""
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


@receiver(user_logged_in)
def log_user_logged_in(sender, request, user, **kwargs):
    logger.info(
        "login_success username=%s user_id=%s ip=%s",
        getattr(user, "username", ""),
        getattr(user, "pk", ""),
        _client_ip(request),
    )


@receiver(user_logged_out)
def log_user_logged_out(sender, request, user, **kwargs):
    logger.info(
        "logout username=%s user_id=%s ip=%s",
        getattr(user, "username", "") if user else "",
        getattr(user, "pk", "") if user else "",
        _client_ip(request),
    )


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    username = (credentials or {}).get("username", "")
    logger.warning("login_failed username=%s ip=%s", username, _client_ip(request))
