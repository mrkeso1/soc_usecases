import calendar
from datetime import date, datetime, timedelta

from django.conf import settings
from django.db import models
from django.db.models import Q


def add_months(source_date, months):
    month = source_date.month - 1 + months
    year = source_date.year + month // 12
    month = month % 12 + 1
    day = min(source_date.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


class MitreAttack(models.Model):
    external_id = models.CharField("ID ATT&CK", max_length=20, unique=True)
    name = models.CharField("Nombre", max_length=255)
    tactic = models.CharField("Táctica", max_length=100, blank=True)
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
        ordering = ["external_id"]

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


class D3Fend(models.Model):
    code = models.CharField("Código D3FEND", max_length=120, unique=True)
    name = models.CharField("Nombre", max_length=255, blank=True)
    category = models.CharField("Categoría", max_length=100, blank=True)

    description = models.TextField(
        "Descripción",
        blank=True,
        default="",
        help_text="Descripción de la técnica D3FEND.",
    )

    is_enabled = models.BooleanField("Habilitada", default=True)

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

    related_attacks = models.ManyToManyField(
        MitreAttack,
        blank=True,
        related_name="related_d3fends",
        verbose_name="ATT&CK relacionados por D3FEND",
        help_text="Relación inferida por D3FEND entre esta técnica defensiva y técnicas ATT&CK.",
    )

    class Meta:
        ordering = ["code"]

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


class DashboardReportSettings(models.Model):
    name = models.CharField(max_length=100, default="Reporte principal", unique=True)
    is_active = models.BooleanField(default=True)
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
        verbose_name = "Configuración reporte dashboard"
        verbose_name_plural = "Configuraciones reporte dashboard"
        constraints = [
            models.UniqueConstraint(
                fields=["is_active"],
                condition=Q(is_active=True),
                name="unique_active_dashboard_report_settings",
            )
        ]

    def __str__(self):
        return f"{self.name} ({'Activo' if self.is_active else 'Inactivo'})"

    def save(self, *args, **kwargs):
        if self.is_active:
            qs = DashboardReportSettings.objects.filter(is_active=True)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            qs.update(is_active=False)
        super().save(*args, **kwargs)


class LifecycleSettings(models.Model):
    name = models.CharField(max_length=100, default="Política principal", unique=True)
    review_interval_days = models.PositiveIntegerField("Días entre controles", default=120)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Configuración ciclo de vida"
        verbose_name_plural = "Configuraciones ciclo de vida"
        constraints = [
            models.UniqueConstraint(
                fields=["is_active"],
                condition=Q(is_active=True),
                name="unique_active_lifecycle_settings",
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.review_interval_days} días)"

    def save(self, *args, **kwargs):
        if self.is_active:
            qs = LifecycleSettings.objects.filter(is_active=True)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            qs.update(is_active=False)
        super().save(*args, **kwargs)


def get_review_interval_days() -> int:
    settings_obj = LifecycleSettings.objects.filter(is_active=True).order_by("-id").first()
    if settings_obj and settings_obj.review_interval_days > 0:
        return settings_obj.review_interval_days
    return 120


class UseCase(models.Model):
    BLOCKING_TYPE_CHOICES = [
        ("Manual", "Manual"),
        ("Automático", "Automático"),
        ("Semiautomático", "Semiautomático"),
    ]

    STATUS_CHOICES = [
        ("Test", "Test"),
        ("Producción", "Producción"),
        ("Desarrollo", "Desarrollo"),
        ("Baja", "Baja"),
        ("Propuesta", "Propuesta"),
    ]

    ESCALATION_CHOICES = [
        ("IRT", "IRT"),
        ("SOC", "SOC"),
        ("Otro", "Otro"),
    ]

    YES_NO_CHOICES = [
        ("Sí", "Sí"),
        ("No", "No"),
    ]

    VALIDATION_STATUS_CHOICES = [
        ("Finalizado", "Finalizado"),
        ("En progreso", "En progreso"),
        ("No realizado", "No realizado"),
    ]

    VALIDATION_RESULT_CHOICES = [
        ("Nada", "Nada"),
        ("OK", "OK"),
        ("Advertencia", "Advertencia"),
        ("Falló", "Falló"),
    ]

    SEVERITY_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    ]

    group_name = models.CharField("Grupo", max_length=100, blank=True)
    device = models.CharField("Dispositivo", max_length=150, blank=True)
    case_type = models.CharField("Tipo", max_length=100, blank=True)
    objective = models.TextField("Objetivo", blank=True)

    blocking_type = models.CharField(
        "Tipo de bloqueo",
        max_length=20,
        choices=BLOCKING_TYPE_CHOICES,
        blank=True,
    )

    name = models.CharField("Nombre NetWitness", max_length=255)
    owner_name = models.CharField("Responsable desarrollo", max_length=150, blank=True)
    lifecycle_control_owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name="Responsable control",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="lifecycle_control_usecases",
    )
    monitoring = models.CharField("Monitoreo", max_length=100, blank=True)

    status = models.CharField(
        "Estado",
        max_length=20,
        choices=STATUS_CHOICES,
        blank=True,
    )

    created_or_adjusted_at = models.DateField("Fecha alta/ajuste", null=True, blank=True)
    production_date = models.DateField("Fecha puesta en producción", null=True, blank=True)

    mitre_attacks = models.ManyToManyField(
        MitreAttack,
        blank=True,
        related_name="use_cases",
        verbose_name="MITRE ATT&CK relacionado",
    )

    d3fends = models.ManyToManyField(
        D3Fend,
        blank=True,
        related_name="use_cases",
        verbose_name="D3FEND relacionado",
    )

    severity = models.CharField(
        "Severidad",
        max_length=20,
        choices=SEVERITY_CHOICES,
        blank=True,
    )

    escalation = models.CharField(
        "Escalamiento",
        max_length=10,
        choices=ESCALATION_CHOICES,
        blank=True,
    )

    sent_to_ho = models.CharField(
        "Envío HO",
        max_length=3,
        choices=YES_NO_CHOICES,
        blank=True,
    )

    ho_flag = models.CharField("HO", max_length=50, blank=True)

    last_validation_date = models.DateField("Última validación", null=True, blank=True)

    validation_status = models.CharField(
        "Estado de validación",
        max_length=20,
        choices=VALIDATION_STATUS_CHOICES,
        default="No realizado",
    )

    validation_result = models.CharField(
        "Resultado",
        max_length=20,
        choices=VALIDATION_RESULT_CHOICES,
        default="Nada",
    )

    is_enabled = models.BooleanField("Habilitado", default=True)

    last_review_date = models.DateField("Última revisión", null=True, blank=True)
    next_review_date = models.DateField("Próxima revisión", null=True, blank=True)
    comments = models.TextField("Comentarios", blank=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_usecases",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="updated_usecases",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        permissions = [
            ("approve_usecase", "Can approve use case"),
            ("promote_usecase", "Can promote use case to production"),
            ("review_usecase", "Can review use case"),
            ("manage_lifecycle_controls", "Can manage all lifecycle controls"),
            ("retire_usecase", "Can retire use case"),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if isinstance(self.last_validation_date, str):
            raw = self.last_validation_date.strip()
            if raw:
                try:
                    self.last_validation_date = datetime.strptime(raw, "%Y-%m-%d").date()
                except ValueError:
                    self.last_validation_date = None
            else:
                self.last_validation_date = None

        if self.last_validation_date:
            interval_days = get_review_interval_days()
            self.next_review_date = self.last_validation_date + timedelta(days=interval_days)
        else:
            self.next_review_date = None

        super().save(*args, **kwargs)

    @property
    def is_review_overdue(self):
        return bool(self.next_review_date and self.next_review_date < date.today())

    @property
    def days_until_review(self):
        if not self.next_review_date:
            return None
        return (self.next_review_date - date.today()).days

    @property
    def review_countdown_label(self):
        days = self.days_until_review
        if days is None:
            return "Sin fecha"
        if days < 0:
            return f"Vencido hace {abs(days)} días"
        if days == 0:
            return "Vence hoy"
        return f"Faltan {days} días"


class LifecycleReview(models.Model):
    use_case = models.ForeignKey(
        UseCase,
        on_delete=models.CASCADE,
        related_name="lifecycle_reviews",
        verbose_name="Caso de uso",
    )
    control_owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="lifecycle_reviews_owned",
        verbose_name="Responsable control",
    )
    completed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="lifecycle_reviews_completed",
        verbose_name="Finalizado por",
    )
    status = models.CharField("Estado", max_length=20, default="Finalizado")
    result = models.CharField("Resultado", max_length=20, blank=True, default="")
    notes = models.TextField("Notas", blank=True)
    checked_at = models.DateField("Fecha control", default=date.today)
    next_review_date = models.DateField("Próximo control", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-checked_at", "-created_at"]
        verbose_name = "Historial de revisión"
        verbose_name_plural = "Historial de revisiones"

    def __str__(self):
        return f"{self.use_case.name} - {self.checked_at}"


class UseCaseChangeLog(models.Model):
    FIELD_LABELS = {
        "group_name": "Grupo",
        "device": "Dispositivo",
        "case_type": "Tipo",
        "objective": "Objetivo",
        "blocking_type": "Tipo de bloqueo",
        "name": "Nombre",
        "owner_name": "Responsable desarrollo",
        "monitoring": "Monitoreo",
        "status": "Estado",
        "created_or_adjusted_at": "Fecha alta/ajuste",
        "production_date": "Fecha puesta en producción",
        "severity": "Severidad",
        "escalation": "Escalamiento",
        "sent_to_ho": "Envío HO",
        "ho_flag": "HO",
        "last_validation_date": "Última validación",
        "validation_status": "Estado ciclo de vida",
        "validation_result": "Resultado",
        "is_enabled": "Habilitado",
        "last_review_date": "Última revisión",
        "next_review_date": "Próxima revisión",
        "comments": "Comentarios",
    }

    use_case = models.ForeignKey(
        UseCase,
        on_delete=models.CASCADE,
        related_name="change_logs",
    )
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="usecase_changes",
    )
    field_name = models.CharField("Campo", max_length=100)
    old_value = models.TextField("Valor anterior", blank=True)
    new_value = models.TextField("Valor nuevo", blank=True)
    changed_at = models.DateTimeField("Fecha cambio", auto_now_add=True)

    class Meta:
        ordering = ["-changed_at"]

    def __str__(self):
        return f"{self.use_case.name} - {self.field_name}"

    @property
    def field_label(self):
        return self.FIELD_LABELS.get(self.field_name, self.field_name)

    def _pretty_value(self, value):
        if value in (None, ""):
            return "-"
        if value == "True":
            return "Sí"
        if value == "False":
            return "No"
        return value

    @property
    def old_value_pretty(self):
        return self._pretty_value(self.old_value)

    @property
    def new_value_pretty(self):
        return self._pretty_value(self.new_value)
