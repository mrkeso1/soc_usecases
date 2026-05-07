from django.contrib import admin
from .models import D3Fend, LifecycleReview, LifecycleSettings, MitreAttack, UseCase, UseCaseChangeLog


@admin.register(MitreAttack)
class MitreAttackAdmin(admin.ModelAdmin):
    list_display = ("external_id", "name", "tactic", "is_enabled")
    list_filter = ("is_enabled",)
    list_editable = ("is_enabled",)
    search_fields = ("external_id", "name", "tactic")


@admin.register(D3Fend)
class D3FendAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "category", "is_enabled")
    list_filter = ("is_enabled",)
    list_editable = ("is_enabled",)
    search_fields = ("code", "name", "category")


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
    filter_horizontal = ("mitre_attacks", "d3fends")


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
