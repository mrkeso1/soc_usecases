from django.apps import AppConfig


class AuditlogConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.auditlog"
    verbose_name = "Auditoria"

    def ready(self):
        from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
        from django.dispatch import receiver

        from .service import audit

        @receiver(user_logged_in, dispatch_uid="soc_audit_user_logged_in")
        def _audit_login(sender, request, user, **kwargs):
            audit(request, "login", "user", user.pk, actor=user)

        @receiver(user_logged_out, dispatch_uid="soc_audit_user_logged_out")
        def _audit_logout(sender, request, user, **kwargs):
            audit(request, "logout", "user", user.pk if user else "", actor=user)

        @receiver(user_login_failed, dispatch_uid="soc_audit_user_login_failed")
        def _audit_login_failed(sender, credentials, request, **kwargs):
            username = (credentials or {}).get("username", "")
            audit(request, "login_failed", "user", username, {"username": username}, actor=None)
