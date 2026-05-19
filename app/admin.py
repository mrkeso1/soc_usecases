from django.contrib import admin
from django.db.models import Count, Q
from django.utils.html import format_html, format_html_join

from .models import (
    D3Fend,
    DashboardReportSettings,
    LifecycleReview,
    LifecycleSettings,
    MitreAttack,
    UseCase,
    UseCaseChangeLog,
)


class HasRelatedD3FendFilter(admin.SimpleListFilter):
    title = "Tiene D3FEND"
    parameter_name = "has_d3fend"

    def lookups(self, request, model_admin):
        return (
            ("yes", "Sí"),
            ("no", "No"),
        )

    def queryset(self, request, queryset):
        if self.value() == "yes":
            return queryset.filter(related_d3fends__isnull=False).distinct()
        if self.value() == "no":
            return queryset.filter(related_d3fends__isnull=True)
        return queryset


class HasRelatedAttackFilter(admin.SimpleListFilter):
    title = "Tiene ATT&CK"
    parameter_name = "has_attack"

    def lookups(self, request, model_admin):
        return (
            ("yes", "Sí"),
            ("no", "No"),
        )

    def queryset(self, request, queryset):
        if self.value() == "yes":
            return queryset.filter(related_attacks__isnull=False).distinct()
        if self.value() == "no":
            return queryset.filter(related_attacks__isnull=True)
        return queryset


@admin.register(MitreAttack)
class MitreAttackAdmin(admin.ModelAdmin):
    list_display = (
        "external_id",
        "name",
        "tactic",
        "is_enabled",
        "d3fend_count",
        "enabled_d3fend_count",
        "disabled_reason_short",
    )
    list_filter = (
        "is_enabled",
        "tactic",
        HasRelatedD3FendFilter,
    )
    list_editable = (
        "is_enabled",
    )
    search_fields = (
        "external_id",
        "name",
        "tactic",
        "disabled_reason",
        "notes",
        "related_d3fends__code",
        "related_d3fends__name",
        "related_d3fends__category",
    )
    readonly_fields = (
        "d3fend_count",
        "enabled_d3fend_count",
        "d3fend_full_list",
    )
    fields = (
        "external_id",
        "name",
        "tactic",
        "is_enabled",
        "disabled_reason",
        "notes",
        "d3fend_count",
        "enabled_d3fend_count",
        "d3fend_full_list",
    )
    ordering = (
        "external_id",
    )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.annotate(
            _d3fend_count=Count("related_d3fends", distinct=True),
            _enabled_d3fend_count=Count(
                "related_d3fends",
                filter=Q(related_d3fends__is_enabled=True),
                distinct=True,
            ),
        )

    @admin.display(description="D3FEND relacionados", ordering="_d3fend_count")
    def d3fend_count(self, obj):
        return getattr(obj, "_d3fend_count", obj.related_d3fends.count())

    @admin.display(description="D3FEND habilitados", ordering="_enabled_d3fend_count")
    def enabled_d3fend_count(self, obj):
        return getattr(
            obj,
            "_enabled_d3fend_count",
            obj.related_d3fends.filter(is_enabled=True).count(),
        )

    @admin.display(description="Motivo baja")
    def disabled_reason_short(self, obj):
        if obj.is_enabled:
            return "-"

        if not getattr(obj, "disabled_reason", ""):
            return "Sin motivo"

        if len(obj.disabled_reason) > 80:
            return f"{obj.disabled_reason[:80]}..."

        return obj.disabled_reason

    @admin.display(description="D3FEND relacionados")
    def d3fend_full_list(self, obj):
        if not obj.pk:
            return "-"

        d3fends = obj.related_d3fends.all().order_by("code", "name")

        if not d3fends:
            return "-"

        return format_html(
            "<ul>{}</ul>",
            format_html_join(
                "",
                (
                    "<li>"
                    "<strong>{}</strong> - {} "
                    "<em>({} / {})</em>{}"
                    "</li>"
                ),
                (
                    (
                        d3.code,
                        d3.name or "-",
                        d3.category or "Sin categoría",
                        "Habilitada" if d3.is_enabled else "Deshabilitada",
                        f" — Motivo: {d3.disabled_reason}" if d3.disabled_reason else "",
                    )
                    for d3 in d3fends
                ),
            ),
        )


@admin.register(D3Fend)
class D3FendAdmin(admin.ModelAdmin):
    list_display = (
        "code",
        "name",
        "category",
        "is_enabled",
        "attack_count",
        "usecase_count",
        "disabled_reason_short",
    )
    list_filter = (
        "is_enabled",
        "category",
        HasRelatedAttackFilter,
    )
    list_editable = (
        "is_enabled",
    )
    search_fields = (
        "code",
        "name",
        "category",
        "description",
        "disabled_reason",
        "notes",
        "related_attacks__external_id",
        "related_attacks__name",
        "related_attacks__tactic",
    )
    filter_horizontal = (
        "related_attacks",
    )
    readonly_fields = (
        "attack_count",
        "usecase_count",
        "related_attacks_full_list",
    )
    fieldsets = (
        (
            "Datos principales",
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
            "Estado y trazabilidad",
            {
                "fields": (
                    "is_enabled",
                    "disabled_reason",
                    "notes",
                )
            },
        ),
        (
            "Relaciones ATT&CK",
            {
                "fields": (
                    "related_attacks",
                    "attack_count",
                    "related_attacks_full_list",
                )
            },
        ),
        (
            "Uso en casos de uso",
            {
                "fields": (
                    "usecase_count",
                )
            },
        ),
    )
    actions = (
        "enable_selected",
        "disable_selected",
        "disable_non_detect_selected",
    )
    ordering = (
        "code",
        "name",
    )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.annotate(
            _attack_count=Count("related_attacks", distinct=True),
            _usecase_count=Count("use_cases", distinct=True),
        )

    @admin.display(description="ATT&CK relacionados", ordering="_attack_count")
    def attack_count(self, obj):
        return getattr(obj, "_attack_count", obj.related_attacks.count())

    @admin.display(description="Casos de uso", ordering="_usecase_count")
    def usecase_count(self, obj):
        return getattr(obj, "_usecase_count", obj.use_cases.count())

    @admin.display(description="Motivo baja")
    def disabled_reason_short(self, obj):
        if obj.is_enabled:
            return "-"

        if not obj.disabled_reason:
            return "Sin motivo"

        if len(obj.disabled_reason) > 80:
            return f"{obj.disabled_reason[:80]}..."

        return obj.disabled_reason

    @admin.display(description="ATT&CK relacionados")
    def related_attacks_full_list(self, obj):
        if not obj.pk:
            return "-"

        attacks = obj.related_attacks.all().order_by("external_id", "name")

        if not attacks:
            return "-"

        return format_html(
            "<ul>{}</ul>",
            format_html_join(
                "",
                (
                    "<li>"
                    "<strong>{}</strong> - {} "
                    "<em>({} / {})</em>"
                    "</li>"
                ),
                (
                    (
                        attack.external_id,
                        attack.name or "-",
                        attack.tactic or "Sin táctica",
                        "Habilitada" if attack.is_enabled else "Deshabilitada",
                    )
                    for attack in attacks
                ),
            ),
        )

    @admin.action(description="Habilitar D3FEND seleccionados")
    def enable_selected(self, request, queryset):
        updated = queryset.update(
            is_enabled=True,
            disabled_reason="",
        )
        self.message_user(request, f"D3FEND habilitados: {updated}")

    @admin.action(description="Deshabilitar D3FEND seleccionados")
    def disable_selected(self, request, queryset):
        updated = queryset.update(
            is_enabled=False,
            disabled_reason="Deshabilitado manualmente desde Django Admin.",
        )
        self.message_user(request, f"D3FEND deshabilitados: {updated}")

    @admin.action(description="Deshabilitar seleccionados si no son Detect")
    def disable_non_detect_selected(self, request, queryset):
        qs = queryset.exclude(category__iexact="Detect")
        updated = qs.update(
            is_enabled=False,
            disabled_reason=(
                "Se deshabilita porque no pertenece a la categoría Detect. "
                "Se conserva en catálogo para referencia y trazabilidad."
            ),
        )
        self.message_user(request, f"D3FEND no Detect deshabilitados: {updated}")


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
    autocomplete_fields = (
        "lifecycle_control_owner",
    )
    filter_horizontal = (
        "mitre_attacks",
        "d3fends",
    )
    readonly_fields = (
        "mitre_count",
        "d3fend_count",
    )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.annotate(
            _mitre_count=Count("mitre_attacks", distinct=True),
            _d3fend_count=Count("d3fends", distinct=True),
        )

    @admin.display(description="ATT&CK", ordering="_mitre_count")
    def mitre_count(self, obj):
        return getattr(obj, "_mitre_count", obj.mitre_attacks.count())

    @admin.display(description="D3FEND", ordering="_d3fend_count")
    def d3fend_count(self, obj):
        return getattr(obj, "_d3fend_count", obj.d3fends.count())


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
    list_filter = (
        "status",
        "result",
        "checked_at",
        "control_owner",
    )
    autocomplete_fields = (
        "use_case",
        "control_owner",
        "completed_by",
    )


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
    list_display = (
        "name",
        "review_interval_days",
        "is_active",
    )
    list_filter = (
        "is_active",
    )
    search_fields = (
        "name",
    )


@admin.register(DashboardReportSettings)
class DashboardReportSettingsAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "is_active",
        "report_title",
        "updated_at",
    )
    list_filter = (
        "is_active",
    )
    search_fields = (
        "name",
        "report_title",
        "report_subtitle",
        "footer_text",
    )
