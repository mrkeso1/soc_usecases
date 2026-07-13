from datetime import date, datetime, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.mitre.attack_ids import attack_family_query
from apps.mitre.models import D3Fend, MitreAttack


class UseCase(models.Model):
    STATUS_TEST = "Test"
    STATUS_PRODUCTION = "Producción"
    STATUS_DEVELOPMENT = "Desarrollo"
    STATUS_RETIRED = "Baja"
    STATUS_PROPOSAL = "Propuesta"

    VALIDATION_STATUS_FINISHED = "Finalizado"
    VALIDATION_STATUS_IN_PROGRESS = "En progreso"
    VALIDATION_STATUS_NOT_DONE = "No realizado"

    VALIDATION_RESULT_NONE = "Nada"
    VALIDATION_RESULT_OK = "OK"
    VALIDATION_RESULT_WARNING = "Advertencia"
    VALIDATION_RESULT_FAILED = "Falló"

    BLOCKING_TYPE_CHOICES = [
        ("Manual", "Manual"),
        ("Automático", "Automático"),
        ("Semiautomático", "Semiautomático"),
    ]

    STATUS_CHOICES = [
        (STATUS_TEST, STATUS_TEST),
        (STATUS_PRODUCTION, STATUS_PRODUCTION),
        (STATUS_DEVELOPMENT, STATUS_DEVELOPMENT),
        (STATUS_RETIRED, STATUS_RETIRED),
        (STATUS_PROPOSAL, STATUS_PROPOSAL),
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
        (VALIDATION_STATUS_FINISHED, VALIDATION_STATUS_FINISHED),
        (VALIDATION_STATUS_IN_PROGRESS, VALIDATION_STATUS_IN_PROGRESS),
        (VALIDATION_STATUS_NOT_DONE, VALIDATION_STATUS_NOT_DONE),
    ]

    VALIDATION_RESULT_CHOICES = [
        (VALIDATION_RESULT_NONE, VALIDATION_RESULT_NONE),
        (VALIDATION_RESULT_OK, VALIDATION_RESULT_OK),
        (VALIDATION_RESULT_WARNING, VALIDATION_RESULT_WARNING),
        (VALIDATION_RESULT_FAILED, VALIDATION_RESULT_FAILED),
    ]

    SEVERITY_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    ]

    group_name = models.CharField("Grupo", max_length=255, blank=True)
    device = models.CharField("Dispositivo", max_length=255, blank=True)
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
        default=VALIDATION_STATUS_NOT_DONE,
    )

    validation_result = models.CharField(
        "Resultado",
        max_length=20,
        choices=VALIDATION_RESULT_CHOICES,
        default=VALIDATION_RESULT_NONE,
    )

    is_enabled = models.BooleanField("Habilitado", default=True)

    last_review_date = models.DateField("Última revisión", null=True, blank=True)
    next_review_date = models.DateField("Próxima revisión", null=True, blank=True)
    disabled_reason = models.TextField(
        "Motivo de deshabilitación",
        blank=True,
        default="",
        help_text="Motivo obligatorio cuando el caso de uso se deshabilita.",
    )
    comments = models.TextField("Comentarios", blank=True)
    full_rule_text = models.TextField("Regla completa", blank=True, default="")
    functional_description = models.TextField("Descripcion funcional", blank=True, default="")

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

    @staticmethod
    def inferred_d3fends_for_attack_ids_queryset(attack_ids):
        attack_ids = list(attack_ids or [])
        if not attack_ids:
            return D3Fend.objects.none()

        selected_external_ids = (
            MitreAttack.objects
            .filter(id__in=attack_ids)
            .values_list("external_id", flat=True)
        )
        expanded_attack_ids = set(
            MitreAttack.objects
            .filter(attack_family_query(selected_external_ids))
            .values_list("id", flat=True)
        )

        return (
            D3Fend.objects
            .filter(
                is_enabled=True,
                related_attacks__is_enabled=True,
                related_attacks__id__in=expanded_attack_ids,
            )
            .prefetch_related("related_attacks")
            .distinct()
            .order_by("code", "name")
        )

    def inferred_d3fends_queryset(self):
        """D3FEND calculado automáticamente desde las técnicas ATT&CK del caso."""
        attack_ids = list(self.mitre_attacks.values_list("id", flat=True))
        return self.inferred_d3fends_for_attack_ids_queryset(attack_ids)

    def inferred_d3fend_ids(self):
        return set(self.inferred_d3fends_queryset().values_list("id", flat=True))

    def sync_d3fends_from_attacks(self) -> bool:
        """Sincroniza el cache D3FEND con lo inferido por ATT&CK."""
        current_ids = set(self.d3fends.values_list("id", flat=True))
        inferred_ids = self.inferred_d3fend_ids()

        if current_ids == inferred_ids:
            return False

        self.d3fends.set(D3Fend.objects.filter(id__in=inferred_ids))
        return True

    def _clean_mitre_attack_ids_for_validation(self):
        pending_ids = getattr(self, "_clean_mitre_attack_ids", None)
        if pending_ids is not None:
            return {str(item).strip() for item in pending_ids if str(item).strip()}
        if self.pk:
            return set(self.mitre_attacks.values_list("id", flat=True))
        return set()

    def clean(self):
        super().clean()
        errors = {}
        status = (self.status or "").strip()
        mitre_attack_ids = self._clean_mitre_attack_ids_for_validation()

        if status == self.STATUS_PRODUCTION and not self.production_date:
            errors["production_date"] = "Para pasar un caso a Producción tenés que cargar la fecha de puesta en producción."

        if status == self.STATUS_PRODUCTION and not mitre_attack_ids:
            errors["mitre_attacks"] = "Un caso en Producción debe tener al menos una técnica MITRE ATT&CK asociada."

        validation_finished = self.validation_status == self.VALIDATION_STATUS_FINISHED
        validation_has_result = self.validation_result in {
            self.VALIDATION_RESULT_OK,
            self.VALIDATION_RESULT_WARNING,
            self.VALIDATION_RESULT_FAILED,
        }

        if validation_finished and self.validation_result == self.VALIDATION_RESULT_NONE:
            errors["validation_result"] = "Si la validación está Finalizada, indicá un resultado distinto de Nada."

        if (validation_finished or validation_has_result) and not self.last_validation_date:
            errors["last_validation_date"] = "Si cargás una validación finalizada o con resultado, indicá la fecha de última validación."

        if self.is_enabled is False and not (self.disabled_reason or "").strip():
            errors["disabled_reason"] = "Indicá el motivo antes de deshabilitar este caso de uso."

        if errors:
            raise ValidationError(errors)

    def set_lifecycle_review_dates(self, checked_at=None):
        from apps.lifecycle.lifecycle import next_configured_deadline
        from apps.lifecycle.models import get_review_interval_days

        checked_at = checked_at or date.today()
        self.last_review_date = checked_at
        self.next_review_date = (
            next_configured_deadline(checked_at, include_current=False)
            or checked_at + timedelta(days=get_review_interval_days())
        )

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


class UseCaseChangeLog(models.Model):
    # Campos auditados por el historial de cambios del caso de uso.
    # Mantener esta lista alineada con usecases.snapshots.snapshot_usecase().
    FIELD_LABELS = {
        "name": "Nombre NetWitness",
        "group_name": "Grupo",
        "device": "Dispositivo",
        "case_type": "Tipo",
        "objective": "Objetivo",
        "blocking_type": "Tipo de bloqueo",
        "owner_name": "Responsable desarrollo",
        "lifecycle_control_owner": "Responsable control",
        "monitoring": "Monitoreo",
        "status": "Estado",
        "created_or_adjusted_at": "Fecha alta/ajuste",
        "production_date": "Fecha puesta en producción",
        "mitre_attacks": "MITRE ATT&CK",
        "d3fends": "D3FEND inferido",
        "severity": "Severidad",
        "escalation": "Escalamiento",
        "sent_to_ho": "Envío HO",
        "ho_flag": "HO",
        "last_validation_date": "Última validación",
        "validation_status": "Estado de validación",
        "validation_result": "Resultado",
        "is_enabled": "Habilitado",
        "disabled_reason": "Motivo de deshabilitación",
        "last_review_date": "Última revisión",
        "next_review_date": "Próxima revisión",
            "comments": "Comentarios",
            "full_rule_text": "Regla completa",
            "functional_description": "Descripcion funcional",
            "rule_conditions": "Condiciones de la regla",
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

    @staticmethod
    def _normalize_snapshot_value(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "Sí" if value else "No"
        if isinstance(value, (date, datetime)):
            return value.strftime("%Y-%m-%d")
        return str(value).strip()

    @classmethod
    def create_diff(cls, usecase, old_data: dict, new_data: dict, user) -> None:
        changed_by = user if getattr(user, "is_authenticated", False) else None
        for field in cls.FIELD_LABELS:
            old_val = cls._normalize_snapshot_value(old_data.get(field))
            new_val = cls._normalize_snapshot_value(new_data.get(field))
            if old_val != new_val:
                cls.objects.create(
                    use_case=usecase,
                    field_name=field,
                    old_value=old_val,
                    new_value=new_val,
                    changed_by=changed_by,
                )

    def __str__(self):
        return f"{self.use_case.name} - {self.field_name}"

    @property
    def field_label(self):
        return self.FIELD_LABELS.get(self.field_name, self.field_name)

    def _pretty_value(self, value):
        if value in (None, ""):
            return "-"
        return value

    @property
    def old_value_pretty(self):
        return self._pretty_value(self.old_value)

    @property
    def new_value_pretty(self):
        return self._pretty_value(self.new_value)


class UseCaseRuleCondition(models.Model):
    TYPE_INCLUDE = "include"
    TYPE_EXCLUDE = "exclude"
    TYPE_CHOICES = [
        (TYPE_INCLUDE, "Incluir"),
        (TYPE_EXCLUDE, "Excluir"),
    ]

    OP_EQUALS = "equals"
    OP_NOT_EQUALS = "not_equals"
    OP_CONTAINS = "contains"
    OP_NOT_CONTAINS = "not_contains"
    OP_STARTS_WITH = "starts_with"
    OP_ENDS_WITH = "ends_with"
    OP_REGEX = "regex"
    OP_EXISTS = "exists"
    OP_NOT_EXISTS = "not_exists"
    OP_IN = "in"
    OP_NOT_IN = "not_in"
    OPERATOR_CHOICES = [
        (OP_EQUALS, "Es igual a"),
        (OP_NOT_EQUALS, "No es igual a"),
        (OP_CONTAINS, "Contiene"),
        (OP_NOT_CONTAINS, "No contiene"),
        (OP_STARTS_WITH, "Empieza con"),
        (OP_ENDS_WITH, "Termina con"),
        (OP_REGEX, "Coincide regex"),
        (OP_EXISTS, "Existe"),
        (OP_NOT_EXISTS, "No existe"),
        (OP_IN, "Esta en lista"),
        (OP_NOT_IN, "No esta en lista"),
    ]

    use_case = models.ForeignKey(
        UseCase,
        on_delete=models.CASCADE,
        related_name="rule_conditions",
        verbose_name="Caso de uso",
    )
    position = models.PositiveIntegerField("Orden", default=1)
    condition_type = models.CharField("Tipo", max_length=12, choices=TYPE_CHOICES, default=TYPE_INCLUDE)
    field_name = models.CharField("Campo", max_length=160)
    operator = models.CharField("Operador", max_length=24, choices=OPERATOR_CHOICES, default=OP_EQUALS)
    value = models.TextField("Valor", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["position", "id"]
        verbose_name = "Condicion de regla"
        verbose_name_plural = "Condiciones de regla"

    def __str__(self):
        return f"{self.get_condition_type_display()} {self.field_name} {self.get_operator_display()} {self.value}".strip()
