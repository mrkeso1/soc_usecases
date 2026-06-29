from django.conf import settings
from django.db import models

from apps.sources.models import EventSource
from apps.usecases.models import UseCase


class Control(models.Model):
    STATUS_DRAFT = "Borrador"
    STATUS_PRODUCTION = "Produccion"
    STATUS_MAINTENANCE = "Mantenimiento"
    STATUS_RETIRED = "Baja"
    STATUS_CHOICES = [
        (STATUS_DRAFT, "Borrador"),
        (STATUS_PRODUCTION, "Produccion"),
        (STATUS_MAINTENANCE, "Mantenimiento"),
        (STATUS_RETIRED, "Baja"),
    ]

    CLASS_INTERNAL = "Proteccion Interna"
    CLASS_PERIMETER = "Proteccion Perimetral"
    CLASS_CLOUD = "Proteccion Cloud"
    CLASS_CHOICES = [
        (CLASS_INTERNAL, "Proteccion Interna"),
        (CLASS_PERIMETER, "Proteccion Perimetral"),
        (CLASS_CLOUD, "Proteccion Cloud"),
    ]

    version = models.PositiveIntegerField(default=1)
    code = models.CharField(max_length=64, unique=True, blank=True)
    name = models.CharField(max_length=255)
    objective = models.TextField(blank=True)
    description = models.TextField(blank=True)
    mitigated_risk = models.TextField(blank=True)
    classification = models.CharField(max_length=80, choices=CLASS_CHOICES, default=CLASS_INTERNAL)
    source = models.ForeignKey(EventSource, on_delete=models.PROTECT, related_name="controls")
    use_cases = models.ManyToManyField(UseCase, blank=True, related_name="controls")
    status = models.CharField(max_length=40, choices=STATUS_CHOICES, default=STATUS_DRAFT)
    deployed_at = models.DateField(null=True, blank=True)
    control_conditions = models.JSONField(default=list, blank=True)
    evidence = models.TextField(blank=True)
    owner = models.CharField(max_length=150, blank=True)
    review_frequency_days = models.PositiveIntegerField(default=90)
    next_review_at = models.DateField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_controls",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="updated_controls",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["code", "name"]

    def save(self, *args, **kwargs):
        if not self.code:
            next_id = (Control.objects.order_by("-id").values_list("id", flat=True).first() or 0) + 1
            self.code = f"CTRL{next_id:04d}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.code} - {self.name}" if self.code else self.name


class ControlVersion(models.Model):
    control = models.ForeignKey(Control, on_delete=models.CASCADE, related_name="versions")
    version = models.PositiveIntegerField()
    changes = models.JSONField(default=dict, blank=True)
    snapshot = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="control_versions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["control_id", "-version"]


class ControlInventoryChange(models.Model):
    ACTION_CREATED = "created"
    ACTION_UPDATED = "updated"
    ACTION_DELETED = "deleted"

    action = models.CharField(max_length=40)
    control = models.ForeignKey(Control, null=True, blank=True, on_delete=models.SET_NULL, related_name="inventory_changes")
    control_code = models.CharField(max_length=64, blank=True)
    control_name = models.CharField(max_length=255, blank=True)
    control_version = models.PositiveIntegerField(null=True, blank=True)
    changes = models.JSONField(default=dict, blank=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="control_inventory_changes",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]

