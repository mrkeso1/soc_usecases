from django import forms
from django.contrib import admin, messages
from django.shortcuts import redirect
from django.urls import path, reverse
from django.utils import timezone
from django.utils.html import format_html, format_html_join

from .framework_sync import run_scheduled_security_frameworks_sync
from .forms import MitreAttackM2MBridgeMixin
from .models import (
    CoverageOverride,
    D3Fend,
    DashboardReportSettings,
    LifecycleReview,
    LifecycleSettings,
    MitreAttack,
    MitreAttackSyncSettings,
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
    return f"{value[:max_length - 1]}..."


@admin.register(CoverageOverride)
class CoverageOverrideAdmin(admin.ModelAdmin):
    list_display = (
        "framework",
        "object_type",
        "object_key",
        "object_name",
        "status",
        "reason_summary",
        "updated_by",
        "updated_at",
    )
    list_filter = ("framework", "object_type", "status")
    search_fields = ("object_key", "object_name", "reason")
    readonly_fields = ("created_at", "updated_at")

    @admin.display(description="Motivo / evidencia")
    def reason_summary(self, obj):
        return _short_text(obj.reason)


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


@admin.register(MitreAttackSyncSettings)
class MitreAttackSyncSettingsAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "is_active",
        "interval_value",
        "interval_unit",
        "status_badge",
        "last_success_display",
        "next_run_display",
        "run_now_link",
        "last_created",
        "last_updated",
        "last_skipped",
    )
    list_filter = ("is_active", "interval_unit", "last_status")
    readonly_fields = (
        "last_run_at",
        "last_success_at",
        "last_status",
        "last_message",
        "framework_summary_display",
        "run_now_link",
        "last_created",
        "last_updated",
        "last_skipped",
        "updated_at",
        "next_run_display",
    )
    fieldsets = (
        ("Programacion", {
            "fields": ("name", "is_active", "interval_value", "interval_unit"),
            "description": (
                "El cron externo puede ejecutarse seguido; esta configuracion decide "
                "si ya corresponde sincronizar ATT&CK, D3FEND, mappings y casos."
            ),
        }),
        ("Ultima ejecucion", {
            "fields": (
                "last_status",
                "last_message",
                "framework_summary_display",
                "run_now_link",
                "last_run_at",
                "last_success_at",
                "next_run_display",
                "last_created",
                "last_updated",
                "last_skipped",
                "updated_at",
            ),
        }),
    )

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "<int:object_id>/run-now/",
                self.admin_site.admin_view(self.run_now),
                name="usecases_mitreattacksyncsettings_run_now",
            )
        ]
        return custom_urls + urls

    @admin.display(description="Estado")
    def status_badge(self, obj):
        colors = {
            MitreAttackSyncSettings.STATUS_SUCCESS: ("#047857", "OK"),
            MitreAttackSyncSettings.STATUS_ERROR: ("#b91c1c", "Error"),
            MitreAttackSyncSettings.STATUS_RUNNING: ("#1d4ed8", "En ejecucion"),
            MitreAttackSyncSettings.STATUS_NEVER: ("#6b7280", "Nunca"),
        }
        color, label = colors.get(obj.last_status, ("#6b7280", obj.last_status))
        return format_html('<strong style="color:{};">{}</strong>', color, label)

    @admin.display(description="Ultima OK")
    def last_success_display(self, obj):
        if not obj.last_success_at:
            return "-"
        return timezone.localtime(obj.last_success_at).strftime("%Y-%m-%d %H:%M")

    @admin.display(description="Resumen catalogos y casos")
    def framework_summary_display(self, obj):
        if not obj.last_message:
            return "-"
        return format_html_join("", "{}<br>", ((line,) for line in obj.last_message.splitlines()))

    @admin.display(description="Proxima ejecucion")
    def next_run_display(self, obj):
        next_run = obj.next_run_at()
        if not next_run or obj.is_due():
            return format_html('<strong style="color:#047857;">{}</strong>', "Ahora")
        return timezone.localtime(next_run).strftime("%Y-%m-%d %H:%M")

    @admin.display(description="Accion manual")
    def run_now_link(self, obj):
        if not obj or not obj.pk:
            return "Disponible despues de guardar la configuracion."
        url = reverse("admin:usecases_mitreattacksyncsettings_run_now", args=[obj.pk])
        return format_html(
            '<a class="button" href="{}">Ejecutar sync completo ATT&CK + D3FEND</a>',
            url,
        )

    def run_now(self, request, object_id):
        config = self.get_object(request, object_id)
        if not config:
            self.message_user(request, "No se encontro la configuracion MITRE.", messages.ERROR)
            return redirect("..")

        try:
            result = run_scheduled_security_frameworks_sync(force=True, settings=config)
        except Exception as exc:
            self.message_user(request, f"Fallo la sincronizacion completa: {exc}", messages.ERROR)
        else:
            self.message_user(
                request,
                (
                    "Sincronizacion completa finalizada: ATT&CK actualizado, "
                    "D3FEND actualizado, mappings D3FEND->ATT&CK reconstruidos "
                    "y casos recalculados. "
                    f"ATT&CK creados: {result.created}. "
                    f"ATT&CK actualizados: {result.updated}. "
                    f"ATT&CK omitidos: {result.skipped}."
                ),
                messages.SUCCESS,
            )
        return redirect("../..")


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



class UseCaseBusinessRulesAdminForm(MitreAttackM2MBridgeMixin, forms.ModelForm):
    """Bridge para que UseCase.clean() valide M2M desde Django Admin."""

    pass


@admin.register(UseCase)
class UseCaseAdmin(admin.ModelAdmin):
    form = UseCaseBusinessRulesAdminForm

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
        "disabled_reason_summary",
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
        "disabled_reason",
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
                    "disabled_reason",
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

    @admin.display(description="Motivo deshabilitación")
    def disabled_reason_summary(self, obj):
        if obj.is_enabled:
            return "-"
        return _short_text(obj.disabled_reason)

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

