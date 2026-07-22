from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone


class MitreAttack(models.Model):
    external_id = models.CharField("ID ATT&CK", max_length=20, unique=True)
    name = models.CharField("Nombre", max_length=255)
    tactic = models.CharField("Táctica", max_length=100, blank=True)
    description = models.TextField("Descripción", blank=True, default="")
    translated_description = models.TextField("Descripción en castellano", blank=True, default="")
    is_enabled = models.BooleanField("Habilitada", default=True)
    disabled_reason = models.TextField(
        "Motivo de deshabilitación",
        blank=True,
        default="",
        help_text="Explica por qué esta técnica ATT&CK fue deshabilitada.",
    )
    notes = models.TextField(
        "Notas internas",
        blank=True,
        default="",
        help_text="Notas internas sobre la técnica ATT&CK o su aplicabilidad en el SOC.",
    )

    class Meta:
        db_table = "usecases_mitreattack"
        ordering = ["external_id"]
        verbose_name = "MITRE ATT&CK"
        verbose_name_plural = "MITRE ATT&CK"

    def __str__(self):
        if self.name:
            return f"{self.external_id} - {self.name}"
        return self.external_id

    @property
    def related_d3fends_count(self):
        return self.related_d3fends.count()

    @property
    def related_d3fends_display(self):
        d3fends = self.related_d3fends.all().order_by("code", "name")
        values = []

        for d3fend in d3fends:
            if d3fend.name:
                values.append(f"{d3fend.code} - {d3fend.name}")
            else:
                values.append(d3fend.code)

        return ", ".join(values)

    @property
    def enabled_related_d3fends_display(self):
        d3fends = self.related_d3fends.filter(is_enabled=True).order_by("code", "name")
        values = []

        for d3fend in d3fends:
            if d3fend.name:
                values.append(f"{d3fend.code} - {d3fend.name}")
            else:
                values.append(d3fend.code)

        return ", ".join(values)


class MitreAttackTactic(models.Model):
    external_id = models.CharField("ID ATT&CK", max_length=20, unique=True)
    short_name = models.CharField("Nombre corto", max_length=100, unique=True)
    name = models.CharField("Nombre", max_length=255)
    description = models.TextField("Descripción", blank=True, default="")
    translated_description = models.TextField("Descripción en castellano", blank=True, default="")

    class Meta:
        ordering = ["external_id"]
        verbose_name = "Táctica MITRE ATT&CK"
        verbose_name_plural = "Tácticas MITRE ATT&CK"

    def __str__(self):
        return f"{self.external_id} - {self.name}"


class D3Fend(models.Model):
    code = models.CharField("Código D3FEND", max_length=120, unique=True)
    name = models.CharField("Nombre", max_length=255, blank=True)
    category = models.CharField("Categoría", max_length=100, blank=True)
    is_enabled = models.BooleanField("Habilitada", default=True)
    related_attacks = models.ManyToManyField(
        MitreAttack,
        blank=True,
        db_table="usecases_d3fend_related_attacks",
        related_name="related_d3fends",
        verbose_name="ATT&CK relacionados por D3FEND",
        help_text="Relación inferida por D3FEND entre esta técnica defensiva y técnicas ATT&CK.",
    )
    description = models.TextField(
        "Descripción",
        blank=True,
        default="",
        help_text="Descripción de la técnica D3FEND.",
    )
    translated_description = models.TextField(
        "Descripción en castellano",
        blank=True,
        default="",
        help_text="Traducción local importada. No es sobrescrita por la sincronización oficial.",
    )
    disabled_reason = models.TextField(
        "Motivo de deshabilitación",
        blank=True,
        default="",
        help_text="Explica por qué esta técnica D3FEND fue deshabilitada.",
    )
    notes = models.TextField(
        "Notas internas",
        blank=True,
        default="",
        help_text="Notas internas sobre la técnica D3FEND o su aplicabilidad en el SOC.",
    )

    class Meta:
        db_table = "usecases_d3fend"
        ordering = ["code"]
        verbose_name = "D3FEND"
        verbose_name_plural = "D3FEND"

    def __str__(self):
        if self.name:
            return f"{self.code} - {self.name}"
        return self.code

    @property
    def related_attacks_count(self):
        return self.related_attacks.count()

    @property
    def related_attacks_display(self):
        attacks = self.related_attacks.all().order_by("external_id", "name")
        values = []

        for attack in attacks:
            if attack.name:
                values.append(f"{attack.external_id} - {attack.name}")
            else:
                values.append(attack.external_id)

        return ", ".join(values)

    @property
    def enabled_related_attacks_count(self):
        return self.related_attacks.filter(is_enabled=True).count()


class CoverageOverride(models.Model):
    """Estado manual de cobertura para ATT&CK/D3FEND."""

    FRAMEWORK_ATTACK = "ATTACK"
    FRAMEWORK_D3FEND = "D3FEND"
    FRAMEWORK_CHOICES = [
        (FRAMEWORK_ATTACK, "ATT&CK"),
        (FRAMEWORK_D3FEND, "D3FEND"),
    ]

    OBJECT_TACTIC = "tactic"
    OBJECT_TECHNIQUE = "technique"
    OBJECT_CATEGORY = "category"
    OBJECT_TYPE_CHOICES = [
        (OBJECT_TACTIC, "Táctica ATT&CK"),
        (OBJECT_TECHNIQUE, "Técnica"),
        (OBJECT_CATEGORY, "Categoría D3FEND"),
    ]

    STATUS_ENABLED = "enabled"
    STATUS_FULFILLED = "fulfilled"
    STATUS_DISABLED = "disabled"
    STATUS_CHOICES = [
        (STATUS_ENABLED, "Habilitada"),
        (STATUS_FULFILLED, "Cumplida por herramienta"),
        (STATUS_DISABLED, "Deshabilitada / no aplica"),
    ]

    framework = models.CharField("Framework", max_length=12, choices=FRAMEWORK_CHOICES)
    object_type = models.CharField("Tipo de objeto", max_length=20, choices=OBJECT_TYPE_CHOICES)
    object_key = models.CharField("Clave", max_length=160)
    object_name = models.CharField("Nombre", max_length=255, blank=True, default="")
    status = models.CharField("Estado", max_length=20, choices=STATUS_CHOICES, default=STATUS_ENABLED)
    reason = models.TextField(
        "Motivo / evidencia",
        blank=True,
        default="",
        help_text="Obligatorio si se marca como cumplida por herramienta o deshabilitada/no aplica.",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="coverage_overrides_updated",
        verbose_name="Actualizado por",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "usecases_coverageoverride"
        ordering = ["framework", "object_type", "object_key"]
        verbose_name = "Override de cobertura"
        verbose_name_plural = "Overrides de cobertura"
        constraints = [
            models.UniqueConstraint(
                fields=["framework", "object_type", "object_key"],
                name="unique_coverage_override_target",
            )
        ]

    def __str__(self):
        return f"{self.framework} · {self.object_type} · {self.object_key} · {self.get_status_display()}"

    def clean(self):
        super().clean()
        reason = (self.reason or "").strip()
        if self.status in {self.STATUS_FULFILLED, self.STATUS_DISABLED} and not reason:
            raise ValidationError({"reason": "Indicá el motivo o evidencia para este estado."})


class D3FendAttackRelationOverride(models.Model):
    """Correcciones persistentes sobre relaciones D3FEND->ATT&CK oficiales."""

    ACTION_EXCLUDE = "exclude"
    ACTION_CHOICES = [
        (ACTION_EXCLUDE, "Excluir relacion"),
    ]

    d3fend = models.ForeignKey(
        D3Fend,
        on_delete=models.CASCADE,
        related_name="attack_relation_overrides",
        verbose_name="D3FEND",
    )
    attack = models.ForeignKey(
        MitreAttack,
        on_delete=models.CASCADE,
        related_name="d3fend_relation_overrides",
        verbose_name="ATT&CK",
    )
    action = models.CharField("Accion", max_length=20, choices=ACTION_CHOICES, default=ACTION_EXCLUDE)
    reason = models.TextField(
        "Motivo",
        help_text="Explica por que esta relacion oficial no aplica al modelo SOC local.",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="d3fend_attack_relation_overrides_updated",
        verbose_name="Actualizado por",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "usecases_d3fend_attack_relationoverride"
        ordering = ["d3fend__code", "attack__external_id"]
        verbose_name = "Override relacion D3FEND-ATT&CK"
        verbose_name_plural = "Overrides relaciones D3FEND-ATT&CK"
        constraints = [
            models.UniqueConstraint(
                fields=["d3fend", "attack"],
                name="unique_d3fend_attack_relation_override",
            )
        ]

    def __str__(self):
        return f"{self.d3fend.code} -> {self.attack.external_id}: {self.get_action_display()}"

    def clean(self):
        super().clean()
        if not (self.reason or "").strip():
            raise ValidationError({"reason": "Indica el motivo para auditar esta excepcion."})


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


class MitreAttackSyncSettings(SingleActiveSettingsMixin):
    UNIT_HOURS = "hours"
    UNIT_DAYS = "days"
    UNIT_CHOICES = [
        (UNIT_HOURS, "Horas"),
        (UNIT_DAYS, "Dias"),
    ]

    STATUS_NEVER = "never"
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_ERROR = "error"
    STATUS_CHOICES = [
        (STATUS_NEVER, "Nunca ejecutado"),
        (STATUS_RUNNING, "En ejecucion"),
        (STATUS_SUCCESS, "OK"),
        (STATUS_ERROR, "Error"),
    ]

    name = models.CharField(max_length=100, default="Sincronizacion MITRE principal", unique=True)
    interval_value = models.PositiveIntegerField("Intervalo", default=24)
    interval_unit = models.CharField("Unidad", max_length=10, choices=UNIT_CHOICES, default=UNIT_HOURS)
    d3fend_catalog_base_url = models.URLField(
        "URL base catalogo D3FEND",
        max_length=500,
        blank=True,
        default="https://d3fend.mitre.org/ontologies/d3fend/",
        help_text="Indice oficial donde MITRE publica las versiones del catalogo D3FEND.",
    )
    d3fend_catalog_version = models.CharField(
        "Version catalogo D3FEND",
        max_length=40,
        blank=True,
        default="latest",
        help_text="Usa 'latest' para resolver automaticamente la ultima version publicada.",
    )
    d3fend_catalog_url = models.URLField(
        "URL CSV catalogo D3FEND",
        max_length=500,
        blank=True,
        default="",
        help_text="Opcional. Si se completa, se usa esta URL exacta y no se resuelve version.",
    )
    last_run_at = models.DateTimeField("Última ejecución", null=True, blank=True)
    last_success_at = models.DateTimeField("Última ejecución OK", null=True, blank=True)
    last_status = models.CharField("Ultimo estado", max_length=20, choices=STATUS_CHOICES, default=STATUS_NEVER)
    last_message = models.TextField("Ultimo mensaje", blank=True, default="")
    last_created = models.PositiveIntegerField("Ultimos creados", default=0)
    last_updated = models.PositiveIntegerField("Ultimos actualizados", default=0)
    last_skipped = models.PositiveIntegerField("Ultimos omitidos", default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "usecases_mitreattacksyncsettings"
        verbose_name = "Sincronizacion de frameworks"
        verbose_name_plural = "Sincronizaciones de frameworks"
        constraints = [
            models.UniqueConstraint(
                fields=["is_active"],
                condition=Q(is_active=True),
                name="unique_active_mitre_attack_sync_settings",
            )
        ]

    def __str__(self):
        return f"{self.name} (cada {self.interval_value} {self.get_interval_unit_display().lower()})"

    @classmethod
    def get_active(cls):
        return cls.objects.filter(is_active=True).order_by("-id").first()

    def interval_delta(self):
        if self.interval_unit == self.UNIT_DAYS:
            return timedelta(days=self.interval_value)
        return timedelta(hours=self.interval_value)

    def clean(self):
        super().clean()
        if self.interval_value < 1:
            raise ValidationError({"interval_value": "El intervalo debe ser mayor o igual a 1."})

    def next_run_at(self):
        baseline = self.last_success_at or self.last_run_at
        if not baseline:
            return None
        return baseline + self.interval_delta()

    def is_due(self, now=None) -> bool:
        next_run = self.next_run_at()
        if not next_run:
            return True
        return (now or timezone.now()) >= next_run

    def mark_running(self, when=None):
        self.last_run_at = when or timezone.now()
        self.last_status = self.STATUS_RUNNING
        self.last_message = "Sincronizacion MITRE en ejecucion."
        self.save(update_fields=["last_run_at", "last_status", "last_message", "updated_at"])

    def mark_success(self, result, when=None):
        when = when or timezone.now()
        self.last_run_at = when
        self.last_success_at = when
        self.last_status = self.STATUS_SUCCESS
        self.last_message = result.message or "Sincronizacion MITRE finalizada."
        self.last_created = result.created
        self.last_updated = result.updated
        self.last_skipped = result.skipped
        self.save(update_fields=[
            "last_run_at",
            "last_success_at",
            "last_status",
            "last_message",
            "last_created",
            "last_updated",
            "last_skipped",
            "updated_at",
        ])

    def mark_error(self, message, when=None):
        self.last_run_at = when or timezone.now()
        self.last_status = self.STATUS_ERROR
        self.last_message = str(message or "Error desconocido")[:2000]
        self.save(update_fields=["last_run_at", "last_status", "last_message", "updated_at"])
