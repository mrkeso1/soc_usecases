from django.db import models
from django.db.models import Q


class SingleActiveSettingsMixin(models.Model):
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.is_active:
            qs = type(self).objects.filter(is_active=True)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            qs.update(is_active=False)
        super().save(*args, **kwargs)


class DashboardReportSettings(SingleActiveSettingsMixin):
    name = models.CharField(max_length=100, default="Reporte principal", unique=True)
    logo = models.ImageField("Logo", upload_to="dashboard_reports/logos/", blank=True)
    report_title = models.CharField("Título", max_length=160, default="Reporte ejecutivo SOC")
    report_subtitle = models.CharField(
        "Subtítulo",
        max_length=255,
        default="Cobertura ATT&CK y D3FEND sobre casos de uso en producción",
        blank=True,
    )
    footer_text = models.CharField("Pie de página", max_length=255, blank=True, default="SOC Use Cases Manager")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "usecases_dashboardreportsettings"
        verbose_name = "Configuración reporte dashboard"
        verbose_name_plural = "Configuraciones reporte dashboard"
        permissions = [
            ("view_executive_dashboard", "Can view executive dashboard"),
            ("view_mitre_dashboard", "Can view MITRE dashboard"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["is_active"],
                condition=Q(is_active=True),
                name="unique_active_dashboard_report_settings",
            )
        ]

    def __str__(self):
        return f"{self.name} ({'Activo' if self.is_active else 'Inactivo'})"


class MitreCoverageSnapshot(models.Model):
    snapshot_date = models.DateField("Fecha", unique=True)
    coverage_score = models.DecimalField("Estado cobertura", max_digits=5, decimal_places=1, default=0)
    attack_techniques_covered = models.PositiveIntegerField(default=0)
    attack_techniques_total = models.PositiveIntegerField(default=0)
    attack_techniques_percent = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    attack_tactics_full_covered = models.PositiveIntegerField(default=0)
    attack_tactics_total = models.PositiveIntegerField(default=0)
    attack_tactics_percent = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    d3fend_detect_equivalent_covered = models.DecimalField(max_digits=8, decimal_places=1, default=0)
    d3fend_detect_total = models.PositiveIntegerField(default=0)
    d3fend_detect_percent = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    d3fend_detect_full_covered = models.PositiveIntegerField(default=0)
    d3fend_detect_full_percent = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["snapshot_date"]
        verbose_name = "Snapshot cobertura MITRE"
        verbose_name_plural = "Snapshots cobertura MITRE"

    def __str__(self):
        return f"{self.snapshot_date}: {self.coverage_score}%"
