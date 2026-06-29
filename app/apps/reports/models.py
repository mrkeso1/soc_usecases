from django.conf import settings
from django.db import models


class ReportDownload(models.Model):
    TYPE_EXECUTIVE = "executive"
    TYPE_MITRE = "mitre"
    TYPE_INVENTORY = "inventory"
    TYPE_LIFECYCLE = "lifecycle"
    TYPE_CONTROLS = "controls"
    TYPE_CHOICES = [
        (TYPE_EXECUTIVE, "Ejecutivo"),
        (TYPE_MITRE, "MITRE / D3FEND"),
        (TYPE_INVENTORY, "Inventario"),
        (TYPE_LIFECYCLE, "Ciclo de vida"),
        (TYPE_CONTROLS, "Controles"),
    ]

    report_type = models.CharField(max_length=32, choices=TYPE_CHOICES)
    filename = models.CharField(max_length=180)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="report_downloads",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        verbose_name = "Descarga de reporte"
        verbose_name_plural = "Descargas de reportes"
        permissions = [
            ("export_reports", "Can export reports"),
        ]

    def __str__(self):
        return f"{self.get_report_type_display()} - {self.filename}"


class ReportTemplateConfig(models.Model):
    report_type = models.CharField(max_length=32, choices=ReportDownload.TYPE_CHOICES, unique=True)
    organization_name = models.CharField(max_length=180, default="SOC Control Manager")
    document_label = models.CharField(max_length=180, default="Gobierno de Seguridad")
    report_title = models.CharField(max_length=220, blank=True)
    introduction_text = models.TextField(default="Inventario y trazabilidad operativa", blank=True)
    primary_color = models.CharField(max_length=7, default="#1d4ed8")
    accent_color = models.CharField(max_length=7, default="#22c55e")
    footer_text = models.CharField(max_length=255, default="Documento generado por SOC Control Manager")
    confidentiality_label = models.CharField(max_length=120, default="Uso interno")
    logo = models.FileField(upload_to="reporting/", null=True, blank=True)
    sections = models.JSONField(default=list, blank=True)
    show_header = models.BooleanField(default=True)
    show_footer = models.BooleanField(default=True)
    show_generation_date = models.BooleanField(default=True)
    show_page_numbers = models.BooleanField(default=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="updated_report_templates",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["report_type"]
        verbose_name = "Plantilla de reporte"
        verbose_name_plural = "Plantillas de reportes"
        permissions = [
            ("configure_report_templates", "Can configure report templates"),
        ]

    def __str__(self):
        return f"{self.get_report_type_display()} - {self.organization_name}"
