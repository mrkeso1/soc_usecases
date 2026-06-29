from datetime import date
from decimal import Decimal

from django.conf import settings
from django.db import models
from django.db.models import Q

from apps.usecases.models import UseCase


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


class LifecycleSettings(SingleActiveSettingsMixin):
    name = models.CharField(max_length=100, default="Política principal", unique=True)
    review_interval_days = models.PositiveIntegerField("Días entre controles", default=120)

    class Meta:
        db_table = "usecases_lifecyclesettings"
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


def get_review_interval_days() -> int:
    interval_days = (
        LifecycleSettings.objects
        .filter(is_active=True)
        .order_by("-id")
        .values_list("review_interval_days", flat=True)
        .first()
    )
    return interval_days if interval_days and interval_days > 0 else 120


class LifecycleReview(models.Model):
    RESULT_CURRENT = "Vigente"
    RESULT_CURRENT_WITH_IMPROVEMENTS = "Vigente con mejoras"
    RESULT_UPDATE_REQUIRED = "Requiere actualizacion"
    RESULT_OBSOLETE = "Obsoleta"
    RESULT_RETIREMENT_RECOMMENDED = "Baja recomendada"
    RESULT_CHOICES = [
        (RESULT_CURRENT, "Vigente"),
        (RESULT_CURRENT_WITH_IMPROVEMENTS, "Vigente con mejoras"),
        (RESULT_UPDATE_REQUIRED, "Requiere actualizacion"),
        (RESULT_OBSOLETE, "Obsoleta"),
        (RESULT_RETIREMENT_RECOMMENDED, "Baja recomendada"),
    ]

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
    review_type = models.CharField("Período", max_length=40, default="")
    alert_triggered_90d = models.BooleanField("Alerto en el periodo", default=False)
    trigger_count = models.PositiveIntegerField("Cantidad de alertas", default=0)
    true_incidents = models.PositiveIntegerField("Incidentes reales", default=0)
    false_positives = models.PositiveIntegerField("Falsos positivos", default=0)
    logic_valid = models.BooleanField("Lógica funcional", default=True)
    sources_active = models.BooleanField("Fuentes activas", default=True)
    event_ids_valid = models.BooleanField("Event IDs vigentes", default=True)
    fields_exist = models.BooleanField("Campos existentes", default=True)
    requires_tuning = models.BooleanField("Requiere ajuste", default=False)
    requires_optimization = models.BooleanField("Requiere optimizacion", default=False)
    requires_retirement = models.BooleanField("Requiere baja", default=False)
    status = models.CharField("Estado", max_length=20, default=UseCase.VALIDATION_STATUS_FINISHED)
    result = models.CharField("Resultado", max_length=80, blank=True, default="", choices=RESULT_CHOICES)
    notes = models.TextField("Notas", blank=True)
    checked_at = models.DateField("Fecha control", default=date.today)
    next_review_date = models.DateField("Próximo control", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "usecases_lifecyclereview"
        ordering = ["-checked_at", "-created_at"]
        verbose_name = "Historial de revisión"
        verbose_name_plural = "Historial de revisiones"

    def __str__(self):
        return f"{self.use_case.name} - {self.checked_at}"


class DetectionMetric(models.Model):
    HEALTH_GOOD = "good"
    HEALTH_WARN = "warn"
    HEALTH_BAD = "bad"
    HEALTH_UNKNOWN = "unknown"
    HEALTH_CHOICES = [
        (HEALTH_GOOD, "Bueno"),
        (HEALTH_WARN, "Atencion"),
        (HEALTH_BAD, "Bajo"),
        (HEALTH_UNKNOWN, "Sin datos"),
    ]

    SOURCE_LIFECYCLE_REVIEW = "lifecycle_review"
    SOURCE_MANUAL = "manual"
    SOURCE_CHOICES = [
        (SOURCE_LIFECYCLE_REVIEW, "Revision lifecycle"),
        (SOURCE_MANUAL, "Manual"),
    ]

    use_case = models.ForeignKey(
        UseCase,
        on_delete=models.CASCADE,
        related_name="detection_metrics",
        verbose_name="Caso de uso",
    )
    review = models.ForeignKey(
        LifecycleReview,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="detection_metrics",
        verbose_name="Revision lifecycle",
    )
    period_key = models.CharField("Periodo", max_length=80, blank=True, db_index=True)
    period_start = models.DateField("Inicio periodo", null=True, blank=True)
    period_end = models.DateField("Fin periodo", null=True, blank=True)
    measured_at = models.DateField("Fecha medicion", default=date.today)
    trigger_count = models.PositiveIntegerField("Alertas", default=0)
    true_incidents = models.PositiveIntegerField("Incidentes reales", default=0)
    false_positives = models.PositiveIntegerField("Falsos positivos", default=0)
    precision_rate = models.DecimalField("Precision", max_digits=5, decimal_places=1, default=0)
    effectiveness_score = models.DecimalField("Efectividad", max_digits=5, decimal_places=1, default=0)
    health_status = models.CharField("Estado", max_length=16, choices=HEALTH_CHOICES, default=HEALTH_UNKNOWN)
    source = models.CharField("Origen", max_length=32, choices=SOURCE_CHOICES, default=SOURCE_LIFECYCLE_REVIEW)
    notes = models.TextField("Notas", blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_detection_metrics",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-measured_at", "-id"]
        verbose_name = "Metrica de deteccion"
        verbose_name_plural = "Metricas de deteccion"
        constraints = [
            models.UniqueConstraint(
                fields=["use_case", "period_key", "source"],
                name="unique_detection_metric_by_period_source",
            )
        ]

    def __str__(self):
        return f"{self.use_case.name} - {self.period_key or self.measured_at} - {self.effectiveness_score}"

    @staticmethod
    def precision_from_counts(true_incidents, false_positives):
        total_classified = true_incidents + false_positives
        if total_classified <= 0:
            return Decimal("0.0")
        value = (Decimal(true_incidents) / Decimal(total_classified)) * Decimal("100")
        return value.quantize(Decimal("0.1"))

    @staticmethod
    def health_from_score(score, *, has_classified_alerts=True):
        if not has_classified_alerts:
            return DetectionMetric.HEALTH_UNKNOWN
        if score >= Decimal("80.0"):
            return DetectionMetric.HEALTH_GOOD
        if score >= Decimal("50.0"):
            return DetectionMetric.HEALTH_WARN
        return DetectionMetric.HEALTH_BAD


class LifecycleTransition(models.Model):
    TYPE_REVIEW_COMPLETED = "review_completed"
    TYPE_OWNER_CHANGED = "owner_changed"
    TYPE_PERIOD_RESET = "period_reset"
    TYPE_CYCLE_CLOSED = "cycle_closed"
    TYPE_CYCLE_STARTED = "cycle_started"
    TYPE_CHOICES = [
        (TYPE_REVIEW_COMPLETED, "Revision completada"),
        (TYPE_OWNER_CHANGED, "Responsable cambiado"),
        (TYPE_PERIOD_RESET, "Periodo reiniciado"),
        (TYPE_CYCLE_CLOSED, "Ciclo cerrado"),
        (TYPE_CYCLE_STARTED, "Ciclo iniciado"),
    ]

    use_case = models.ForeignKey(
        UseCase,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="lifecycle_transitions",
        verbose_name="Caso de uso",
    )
    review = models.ForeignKey(
        LifecycleReview,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="transitions",
        verbose_name="Revision",
    )
    cycle = models.ForeignKey(
        "LifecycleCycle",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="transitions",
        verbose_name="Ciclo",
    )
    transition_type = models.CharField("Tipo", max_length=32, choices=TYPE_CHOICES)
    period = models.PositiveSmallIntegerField("Periodo", null=True, blank=True)
    period_key = models.CharField("Periodo texto", max_length=80, blank=True)
    from_state = models.CharField("Estado anterior", max_length=160, blank=True)
    to_state = models.CharField("Estado nuevo", max_length=160, blank=True)
    reason = models.TextField("Motivo", blank=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="lifecycle_transitions",
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        verbose_name = "Transicion lifecycle"
        verbose_name_plural = "Transiciones lifecycle"

    def __str__(self):
        target = self.use_case.name if self.use_case else self.period_key or self.cycle_id or "-"
        return f"{self.get_transition_type_display()} - {target}"


class LifecycleCycle(models.Model):
    STATUS_ACTIVE = "active"
    STATUS_CLOSED = "closed"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Activo"),
        (STATUS_CLOSED, "Cerrado"),
    ]

    year = models.PositiveIntegerField(unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    report_exports = models.JSONField(default=dict, blank=True)
    started_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="started_lifecycle_cycles",
    )
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="closed_lifecycle_cycles",
    )
    started_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-year"]
        verbose_name = "Ciclo anual lifecycle"
        verbose_name_plural = "Ciclos anuales lifecycle"

    def __str__(self):
        return f"{self.year} - {self.get_status_display()}"


class LifecyclePeriod(models.Model):
    cycle = models.ForeignKey(
        LifecycleCycle,
        on_delete=models.CASCADE,
        related_name="configured_periods",
    )
    period = models.PositiveSmallIntegerField()
    label = models.CharField(max_length=120)
    start_date = models.DateField()
    end_date = models.DateField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["cycle__year", "period", "start_date"]
        constraints = [
            models.UniqueConstraint(
                fields=["cycle", "period"],
                name="unique_lifecycle_configured_period",
            )
        ]
        verbose_name = "Periodo lifecycle"
        verbose_name_plural = "Periodos lifecycle"

    def __str__(self):
        return f"{self.cycle.year}-P{self.period} - {self.label}"


class LifecyclePeriodMember(models.Model):
    year = models.PositiveIntegerField()
    period = models.PositiveSmallIntegerField()
    use_case = models.ForeignKey(
        UseCase,
        on_delete=models.CASCADE,
        related_name="lifecycle_period_memberships",
    )
    included_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["year", "period", "use_case__name"]
        constraints = [
            models.UniqueConstraint(
                fields=["year", "period", "use_case"],
                name="unique_lifecycle_period_member",
            )
        ]
        verbose_name = "Miembro de periodo lifecycle"
        verbose_name_plural = "Miembros de periodo lifecycle"

    def __str__(self):
        return f"{self.year}-C{self.period} - {self.use_case_id}"
