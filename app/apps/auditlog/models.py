from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_events",
    )
    action = models.CharField(max_length=120)
    entity_type = models.CharField(max_length=80, blank=True)
    entity_id = models.CharField(max_length=120, blank=True)
    ip_address = models.CharField(max_length=80, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        permissions = [
            ("view_security_audit", "Can view SOC security audit"),
            ("view_inventory_audit", "Can view inventory audit"),
            ("view_lifecycle_audit", "Can view lifecycle audit"),
            ("view_controls_audit", "Can view controls audit"),
            ("view_reports_audit", "Can view reports audit"),
            ("view_sigma_audit", "Can view Sigma audit"),
            ("export_audit", "Can export audit events"),
        ]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.action}"
