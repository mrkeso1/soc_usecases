from django.contrib import admin

from .models import SigmaConversion, UseCaseTechnicalBackup


@admin.register(SigmaConversion)
class SigmaConversionAdmin(admin.ModelAdmin):
    list_display = ("mode", "target", "use_case", "created_by", "created_at")
    list_filter = ("mode", "target", "created_at")
    search_fields = ("use_case__name", "input_text", "output_text", "created_by__username")
    autocomplete_fields = ("use_case", "created_by")
    readonly_fields = ("created_at",)


@admin.register(UseCaseTechnicalBackup)
class UseCaseTechnicalBackupAdmin(admin.ModelAdmin):
    list_display = ("use_case", "version", "backup_type", "short_checksum", "is_current", "created_by", "created_at")
    list_filter = ("backup_type", "is_current", "created_at")
    search_fields = ("use_case__name", "title", "checksum", "logic_text", "sigma_text", "notes")
    autocomplete_fields = ("use_case", "source_conversion", "created_by")
    readonly_fields = ("checksum", "created_at")
