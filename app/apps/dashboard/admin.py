from django.contrib import admin

from .models import DashboardReportSettings, MitreCoverageSnapshot


@admin.register(DashboardReportSettings)
class DashboardReportSettingsAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "report_title", "updated_at")
    list_filter = ("is_active",)
    search_fields = ("name", "report_title", "report_subtitle", "footer_text")


@admin.register(MitreCoverageSnapshot)
class MitreCoverageSnapshotAdmin(admin.ModelAdmin):
    list_display = (
        "snapshot_date",
        "coverage_score",
        "attack_techniques_percent",
        "attack_tactics_percent",
        "d3fend_detect_percent",
        "d3fend_detect_full_percent",
        "updated_at",
    )
    list_filter = ("snapshot_date",)
    readonly_fields = ("created_at", "updated_at", "payload")
    date_hierarchy = "snapshot_date"
