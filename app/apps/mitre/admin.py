from django import forms
from django.contrib import admin, messages
from django.shortcuts import redirect
from django.urls import path, reverse
from django.utils import timezone
from django.utils.html import format_html, format_html_join

from .framework_sync import run_scheduled_security_frameworks_sync
from .models import (
    CoverageOverride,
    D3Fend,
    D3FendAttackRelationOverride,
    MitreAttack,
    MitreAttackSyncSettings,
)


class DisableReasonRequiredForm(forms.ModelForm):
    """Evita deshabilitar una tecnica sin motivo documentado."""

    def clean(self):
        cleaned_data = super().clean()
        is_enabled = cleaned_data.get("is_enabled")
        disabled_reason = (cleaned_data.get("disabled_reason") or "").strip()

        if is_enabled is False and not disabled_reason:
            self.add_error(
                "disabled_reason",
                "Indica el motivo antes de deshabilitar esta tecnica.",
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


@admin.register(D3FendAttackRelationOverride)
class D3FendAttackRelationOverrideAdmin(admin.ModelAdmin):
    list_display = (
        "d3fend",
        "attack",
        "action",
        "reason_summary",
        "updated_by",
        "updated_at",
    )
    list_filter = ("action", "d3fend__category", "attack__tactic")
    search_fields = (
        "d3fend__code",
        "d3fend__name",
        "attack__external_id",
        "attack__name",
        "reason",
    )
    autocomplete_fields = ("d3fend", "attack", "updated_by")
    readonly_fields = ("created_at", "updated_at")

    @admin.display(description="Motivo")
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
            "Estado y motivo de deshabilitacion",
            {
                "fields": (
                    "is_enabled",
                    "disabled_reason",
                    "notes",
                ),
                "description": (
                    "Si la tecnica se deshabilita, deja documentado el motivo "
                    "para auditoria y mantenimiento del catalogo."
                ),
            },
        ),
    )

    @admin.display(description="Motivo deshabilitacion")
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
        ("Fuente D3FEND", {
            "fields": ("d3fend_catalog_base_url", "d3fend_catalog_version", "d3fend_catalog_url"),
            "description": (
                "Usa version 'latest' para resolver automaticamente la ultima version oficial. "
                "Completa URL CSV solo si queres fijar una fuente exacta."
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
                name="mitre_mitreattacksyncsettings_run_now",
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
        url = reverse("admin:mitre_mitreattacksyncsettings_run_now", args=[obj.pk])
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
            "Relacion con ATT&CK",
            {
                "fields": ("related_attacks",),
                "description": "Tecnicas ATT&CK relacionadas con esta tecnica defensiva.",
            },
        ),
        (
            "Estado y motivo de deshabilitacion",
            {
                "fields": (
                    "is_enabled",
                    "disabled_reason",
                    "notes",
                ),
                "description": (
                    "Si la tecnica se deshabilita, deja documentado el motivo "
                    "para auditoria y mantenimiento del catalogo."
                ),
            },
        ),
    )

    @admin.display(description="Motivo deshabilitacion")
    def disabled_reason_summary(self, obj):
        if obj.is_enabled:
            return "-"
        return _short_text(obj.disabled_reason)
