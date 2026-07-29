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


class OperationalAlert(models.Model):
    SEVERITY_INFO = "info"
    SEVERITY_WARNING = "warning"
    SEVERITY_ERROR = "error"
    SEVERITY_CRITICAL = "critical"
    SEVERITY_CHOICES = [
        (SEVERITY_INFO, "Informativa"),
        (SEVERITY_WARNING, "Advertencia"),
        (SEVERITY_ERROR, "Error"),
        (SEVERITY_CRITICAL, "Crítica"),
    ]
    STATUS_OPEN = "open"
    STATUS_ACKNOWLEDGED = "acknowledged"
    STATUS_RESOLVED = "resolved"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Abierta"),
        (STATUS_ACKNOWLEDGED, "Reconocida"),
        (STATUS_RESOLVED, "Resuelta"),
    ]

    code = models.CharField("Código", max_length=100, db_index=True)
    fingerprint = models.CharField("Huella", max_length=255, db_index=True)
    severity = models.CharField(
        "Severidad",
        max_length=20,
        choices=SEVERITY_CHOICES,
        default=SEVERITY_WARNING,
    )
    status = models.CharField(
        "Estado",
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_OPEN,
        db_index=True,
    )
    title = models.CharField("Título", max_length=255)
    message = models.TextField("Mensaje")
    context = models.JSONField("Contexto", default=dict, blank=True)
    occurrences = models.PositiveIntegerField("Ocurrencias", default=1)
    first_seen_at = models.DateTimeField("Primera detección", auto_now_add=True)
    last_seen_at = models.DateTimeField("Última detección", auto_now=True)
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="acknowledged_operational_alerts",
    )
    acknowledged_at = models.DateTimeField("Reconocida", null=True, blank=True)
    resolved_at = models.DateTimeField("Resuelta", null=True, blank=True)

    class Meta:
        ordering = ["-last_seen_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["fingerprint"],
                condition=models.Q(status__in=["open", "acknowledged"]),
                name="uniq_active_operational_alert_fingerprint",
            ),
        ]
        verbose_name = "Alerta operativa"
        verbose_name_plural = "Alertas operativas"

    def __str__(self):
        return f"{self.get_severity_display()}: {self.title}"


class ActionRateLimit(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="action_rate_limits",
        verbose_name="Usuario",
    )
    scope = models.CharField("Acción protegida", max_length=100)
    window_started_at = models.DateTimeField("Inicio de ventana")
    request_count = models.PositiveIntegerField("Solicitudes aceptadas", default=0)
    blocked_count = models.PositiveIntegerField("Solicitudes bloqueadas", default=0)
    last_request_at = models.DateTimeField("Última solicitud")
    updated_at = models.DateTimeField("Actualizado", auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "scope"],
                name="uniq_action_rate_limit_user_scope",
            ),
        ]
        indexes = [
            models.Index(fields=["scope", "last_request_at"]),
        ]
        ordering = ["-last_request_at"]
        verbose_name = "Límite de acción"
        verbose_name_plural = "Límites de acciones"

    def __str__(self):
        return f"{self.user} · {self.scope}"
