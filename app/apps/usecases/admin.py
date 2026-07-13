from django import forms
from django.contrib import admin

from .forms import MitreAttackM2MBridgeMixin
from .models import (
    UseCase,
    UseCaseChangeLog,
    UseCaseRuleCondition,
)


def _short_text(value, max_length=90):
    value = (value or "").strip()
    if not value:
        return "-"
    if len(value) <= max_length:
        return value
    return f"{value[:max_length - 1]}..."


class UseCaseBusinessRulesAdminForm(MitreAttackM2MBridgeMixin, forms.ModelForm):
    """Bridge para que UseCase.clean() valide M2M desde Django Admin."""

    class Meta:
        model = UseCase
        fields = "__all__"
        help_texts = {
            "mitre_attacks": "Selecciona tecnicas ATT&CK habilitadas; D3FEND se recalcula al guardar.",
            "full_rule_text": "Regla completa original. Alimenta backups tecnicos y revisiones de auditoria.",
            "functional_description": "Descripcion legible para analistas, auditoria y revisiones lifecycle.",
            "disabled_reason": "Obligatorio si el caso queda deshabilitado.",
        }


@admin.register(UseCase)
class UseCaseAdmin(admin.ModelAdmin):
    form = UseCaseBusinessRulesAdminForm

    class RuleConditionInline(admin.TabularInline):
        model = UseCaseRuleCondition
        extra = 0
        fields = ("position", "condition_type", "field_name", "operator", "value")

    inlines = (RuleConditionInline,)

    list_display = (
        "case_code",
        "name",
        "group_name",
        "device",
        "status",
        "severity",
        "lifecycle_control_owner",
        "production_date",
        "next_review_date",
        "is_enabled",
        "disabled_reason_summary",
        "mitre_count",
        "d3fend_count",
    )

    search_fields = (
        "case_code",
        "name",
        "group_name",
        "device",
        "owner_name",
        "lifecycle_control_owner__username",
        "lifecycle_control_owner__first_name",
        "lifecycle_control_owner__last_name",
        "comments",
        "disabled_reason",
        "functional_description",
        "full_rule_text",
        "rule_conditions__field_name",
        "rule_conditions__value",
        "mitre_attacks__external_id",
        "mitre_attacks__name",
        "d3fends__code",
        "d3fends__name",
    )

    list_filter = (
        "group_name",
        "device",
        "status",
        "severity",
        "lifecycle_control_owner",
        "is_enabled",
    )

    autocomplete_fields = ("lifecycle_control_owner",)
    filter_horizontal = ("mitre_attacks", "d3fend_exclusions")
    readonly_fields = ("d3fends_inferred_display",)

    fieldsets = (
        (
            "Datos principales",
            {
                "fields": (
                    "case_code",
                    "group_name",
                    "device",
                    "case_type",
                    "objective",
                    "blocking_type",
                    "name",
                    "owner_name",
                    "lifecycle_control_owner",
                    "monitoring",
                    "status",
                    "created_or_adjusted_at",
                    "production_date",
                )
            },
        ),
        (
            "Mapeo ATT&CK / D3FEND",
            {
                "fields": (
                    "mitre_attacks",
                    "d3fend_exclusions",
                    "d3fends_inferred_display",
                ),
                "description": (
                    "D3FEND no se carga manualmente. Se calcula automáticamente "
                    "a partir de las técnicas ATT&CK asociadas al caso de uso."
                ),
            },
        ),
        (
            "Clasificación y operación",
            {
                "fields": (
                    "severity",
                    "escalation",
                    "sent_to_ho",
                    "ho_flag",
                    "last_validation_date",
                    "validation_status",
                    "validation_result",
                    "is_enabled",
                    "disabled_reason",
                    "comments",
                    "functional_description",
                    "full_rule_text",
                )
            },
        ),
        (
            "Lifecycle",
            {
                "fields": (
                    "last_review_date",
                    "next_review_date",
                )
            },
        ),
    )

    @admin.display(description="MITRE")
    def mitre_count(self, obj):
        return obj.mitre_attacks.count()

    @admin.display(description="D3FEND inferido")
    def d3fend_count(self, obj):
        return obj.d3fends.count()

    @admin.display(description="D3FEND inferido por ATT&CK")
    def d3fends_inferred_display(self, obj):
        if not obj or not obj.pk:
            return "Se calculará automáticamente después de guardar el caso de uso."

        values = [
            f"{item.code} - {item.name}" if item.name else item.code
            for item in obj.d3fends.all().order_by("code", "name")
        ]
        return ", ".join(values) if values else "Sin D3FEND inferido para los ATT&CK seleccionados."

    @admin.display(description="Motivo deshabilitación")
    def disabled_reason_summary(self, obj):
        if obj.is_enabled:
            return "-"
        return _short_text(obj.disabled_reason)

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        form.instance.sync_d3fends_from_attacks()


@admin.register(UseCaseChangeLog)
class UseCaseChangeLogAdmin(admin.ModelAdmin):
    list_display = (
        "use_case",
        "field_label",
        "old_value_pretty",
        "new_value_pretty",
        "changed_by",
        "changed_at",
    )

    search_fields = (
        "use_case__name",
        "field_name",
        "old_value",
        "new_value",
        "changed_by__username",
    )

    list_filter = (
        "field_name",
        "changed_at",
    )


