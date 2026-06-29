from django.contrib import admin

from .models import (
    DetectionMetric,
    LifecycleCycle,
    LifecyclePeriod,
    LifecyclePeriodMember,
    LifecycleReview,
    LifecycleSettings,
    LifecycleTransition,
)


@admin.register(LifecycleSettings)
class LifecycleSettingsAdmin(admin.ModelAdmin):
    list_display = ("name", "review_interval_days", "is_active")
    list_filter = ("is_active",)
    search_fields = ("name",)


@admin.register(LifecycleReview)
class LifecycleReviewAdmin(admin.ModelAdmin):
    list_display = (
        "use_case",
        "control_owner",
        "completed_by",
        "status",
        "result",
        "trigger_count",
        "true_incidents",
        "false_positives",
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


@admin.register(LifecycleCycle)
class LifecycleCycleAdmin(admin.ModelAdmin):
    list_display = ("year", "status", "started_by", "closed_by", "started_at", "closed_at")
    list_filter = ("status", "year")
    search_fields = ("=year", "started_by__username", "closed_by__username")
    autocomplete_fields = ("started_by", "closed_by")
    readonly_fields = ("started_at", "closed_at")


@admin.register(LifecyclePeriod)
class LifecyclePeriodAdmin(admin.ModelAdmin):
    list_display = ("cycle", "period", "label", "start_date", "end_date", "is_active")
    list_filter = ("cycle__year", "is_active")
    search_fields = ("label", "=cycle__year")
    autocomplete_fields = ("cycle",)


@admin.register(LifecyclePeriodMember)
class LifecyclePeriodMemberAdmin(admin.ModelAdmin):
    list_display = ("year", "period", "use_case", "included_at")
    list_filter = ("year", "period")
    search_fields = ("use_case__name",)
    autocomplete_fields = ("use_case",)
    readonly_fields = ("included_at",)


@admin.register(DetectionMetric)
class DetectionMetricAdmin(admin.ModelAdmin):
    list_display = (
        "use_case",
        "period_key",
        "trigger_count",
        "true_incidents",
        "false_positives",
        "precision_rate",
        "effectiveness_score",
        "health_status",
        "measured_at",
    )
    list_filter = ("health_status", "source", "period_key", "measured_at")
    search_fields = ("use_case__name", "period_key", "notes")
    autocomplete_fields = ("use_case", "review", "created_by")
    readonly_fields = ("created_at", "updated_at")


@admin.register(LifecycleTransition)
class LifecycleTransitionAdmin(admin.ModelAdmin):
    list_display = (
        "transition_type",
        "use_case",
        "period_key",
        "from_state",
        "to_state",
        "actor",
        "created_at",
    )
    list_filter = ("transition_type", "period_key", "created_at")
    search_fields = ("use_case__name", "period_key", "from_state", "to_state", "reason", "actor__username")
    autocomplete_fields = ("use_case", "review", "cycle", "actor")
    readonly_fields = ("created_at",)
