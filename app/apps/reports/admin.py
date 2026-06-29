from django.contrib import admin

from .models import ReportDownload, ReportTemplateConfig


@admin.register(ReportDownload)
class ReportDownloadAdmin(admin.ModelAdmin):
    list_display = ("report_type", "filename", "generated_by", "created_at")
    list_filter = ("report_type", "created_at")
    search_fields = ("filename", "generated_by__username")
    readonly_fields = ("report_type", "filename", "generated_by", "created_at")

    def has_add_permission(self, request):
        return False


@admin.register(ReportTemplateConfig)
class ReportTemplateConfigAdmin(admin.ModelAdmin):
    list_display = ("report_type", "organization_name", "updated_by", "updated_at")
    list_filter = ("report_type",)
    search_fields = ("organization_name", "report_title")
