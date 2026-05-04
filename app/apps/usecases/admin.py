from django.contrib import admin
from .models import UseCase, UseCaseChangeLog, MitreAttack, D3Fend, LifecycleSettings


@admin.register(MitreAttack)
class MitreAttackAdmin(admin.ModelAdmin):
    list_display = ("external_id", "name", "tactic")
    search_fields = ("external_id", "name", "tactic")


@admin.register(D3Fend)
class D3FendAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "category")
    search_fields = ("code", "name", "category")


@admin.register(UseCase)
class UseCaseAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "group_name",
        "device",
        "status",
        "severity",
        "validation_status",
        "validation_result",
        "production_date",
        "next_review_date",
        "is_enabled",
    )
    search_fields = (
        "name",
        "group_name",
        "device",
        "owner_name",
        "comments",
    )
    list_filter = (
        "group_name",
        "device",
        "status",
        "severity",
        "validation_status",
        "validation_result",
        "is_enabled",
    )
    filter_horizontal = ("mitre_attacks", "d3fends")


@admin.register(UseCaseChangeLog)
class UseCaseChangeLogAdmin(admin.ModelAdmin):
    list_display = (
        "use_case",
        "field_name",
        "old_value",
        "new_value",
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
