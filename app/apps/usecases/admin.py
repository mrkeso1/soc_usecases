from django import forms
from django.contrib import admin

from .models import (
    D3Fend,
    DashboardReportSettings,
    LifecycleReview,
    LifecycleSettings,
    MitreAttack,
    UseCase,
    UseCaseChangeLog,
)


class DisableReasonRequiredForm(forms.ModelForm):
    """
    Evita que desde el formulario de administración se deshabilite una técnica
    ATT&CK o D3FEND sin documentar el motivo.
    """

    def clean(self):
        cleaned_data = super().clean()
        is_enabled = cleaned_data.get("is_enabled")
        disabled_reason = (cleaned_data.get("disabled_reason") or "").strip()

        if is_enabled is False and not disabled_reason:
            self.add_error(
                "disabled_reason",
                "Indicá el motivo antes de deshabilitar esta técnica.",
            )

        return cleaned_data


def _short_text(value, max_length=90):
    value = (value or "").strip()
    if not value:
        return "-"
    if len(value) <= max_length:
        return value
    return f"{value[:max_length - 1]}…"


@admin.register(MitreAttack)
class MitreAttackAdmin(admin.ModelAdmin):
    form = DisableReasonRequiredForm

    list_display = (
        "external_id",
        "name",
        "tactic",
        "is_enabled",
        "disabled_reason_summary",
        "related_d3fends_count",
    )
    list_filter = ("is_enabled", "tactic")
    search_fields = (
        "external_id",
        "name",
        "tactic",
        "disabled_reason",
        "notes",
    )
    fieldsets = (
        (
            "Datos ATT&CK",
            {
                "fields": (
                    "external_id",
                    "name",
                    "tactic",
                )
            },
        ),
        (
            "Estado y motivo de deshabilitación",
            {
                "fields": (
                    "is_enabled",
                    "disabled_reason",
                    "notes",
                ),
                "description": (
                    "Si la técnica se deshabilita, dejá documentado el motivo "
                    "para auditoría y mantenimiento del catálogo."
                ),
            },
        ),
    )

    @admin.display(description="Motivo deshabilitación")
    def disabled_reason_summary(self, obj):
        if obj.is_enabled:
            return "-"
        return _short_text(obj.disabled_reason)


@admin.register(D3Fend)
class D3FendAdmin(admin.ModelAdmin):
    form = DisableReasonRequiredForm

    list_display = (
        "code",
        "name",
        "category",
        "is_enabled",
        "disabled_reason_summary",
        "related_attacks_count",
    )
    list_filter = ("is_enabled", "category")
    search_fields = (
        "code",
        "name",
        "category",
        "description",
        "disabled_reason",
        "notes",
        "related_attacks__external_id",
        "related_attacks__name",
    )
    filter_horizontal = ("related_attacks",)
    fieldsets = (
        (
            "Datos D3FEND",
            {
                "fields": (
                    "code",
                    "name",
                    "category",
                    "description",
                )
            },
        ),
        (
            "Relación con ATT&CK",
            {
                "fields": ("related_attacks",),
                "description": "Técnicas ATT&CK relacionadas con esta técnica defensiva.",
            },
        ),
        (
            "Estado y motivo de deshabilitación",
            {
                "fields": (
                    "is_enabled",
                    "disabled_reason",
                    "notes",
                ),
                "description": (
                    "Si la técnica se deshabilita, dejá documentado el motivo "
                    "para auditoría y mantenimiento del catálogo."
                ),
            },
        ),
    )

    @admin.display(description="Motivo deshabilitación")
    def disabled_reason_summary(self, obj):
        if obj.is_enabled:
            return "-"
        return _short_text(obj.disabled_reason)


@admin.register(UseCase)
class UseCaseAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "group_name",
        "device",
        "status",
        "severity",
        "lifecycle_control_owner",
        "production_date",
        "next_review_date",
        "is_enabled",
        "mitre_count",
        "d3fend_count",
    )

    search_fields = (
        "name",
        "group_name",
        "device",
        "owner_name",
        "lifecycle_control_owner__username",
        "lifecycle_control_owner__first_name",
        "lifecycle_control_owner__last_name",
        "comments",
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
    filter_horizontal = ("mitre_attacks",)
    readonly_fields = ("d3fends_inferred_display",)

    fieldsets = (
        (
            "Datos principales",
            {
                "fields": (
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
                    "comments",
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

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        form.instance.sync_d3fends_from_attacks()


@admin.register(LifecycleReview)
class LifecycleReviewAdmin(admin.ModelAdmin):
    list_display = (
        "use_case",
        "control_owner",
        "completed_by",
        "status",
        "result",
        "checked_at",
        "next_review_date",
    )

    search_fields = (
        "use_case__name",
        "control_owner__username",
        "completed_by__username",
        "notes",
    )

    list_filter = ("status", "result", "checked_at", "control_owner")
    autocomplete_fields = ("use_case", "control_owner", "completed_by")


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


@admin.register(LifecycleSettings)
class LifecycleSettingsAdmin(admin.ModelAdmin):
    list_display = ("name", "review_interval_days", "is_active")
    list_filter = ("is_active",)
    search_fields = ("name",)


@admin.register(DashboardReportSettings)
class DashboardReportSettingsAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "report_title", "updated_at")
    list_filter = ("is_active",)
    search_fields = ("name", "report_title", "report_subtitle", "footer_text")
