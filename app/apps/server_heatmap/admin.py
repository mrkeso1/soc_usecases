from django.contrib import admin, messages

from .classification import apply_automatic_classification
from .models import (
    AssetIdentifier,
    InventoryObservation,
    InventorySyncRun,
    ReconciliationIssue,
    ServerAsset,
    ServerCategory,
    ServerInventoryConfiguration,
    ServerNamingRule,
)


@admin.register(ServerCategory)
class ServerCategoryAdmin(admin.ModelAdmin):
    list_display = ("order", "name", "code", "is_active")
    list_filter = ("is_active",)
    search_fields = ("name", "code", "description")
    ordering = ("order", "name")


@admin.action(description="Habilitar equipos seleccionados")
def enable_assets(modeladmin, request, queryset):
    updated = queryset.update(is_enabled=True)
    messages.success(request, f"{updated} equipo(s) habilitado(s).")


@admin.action(description="Deshabilitar equipos seleccionados")
def disable_assets(modeladmin, request, queryset):
    updated = queryset.update(is_enabled=False)
    messages.success(request, f"{updated} equipo(s) deshabilitado(s).")


@admin.action(description="Reaplicar reglas de nomenclatura")
def reclassify_assets(modeladmin, request, queryset):
    updated = 0
    for asset in queryset.filter(classification_source=ServerAsset.CLASSIFICATION_AUTO):
        apply_automatic_classification(asset)
        updated += 1
    messages.success(request, f"{updated} equipo(s) reclasificado(s).")


@admin.register(ServerAsset)
class ServerAssetAdmin(admin.ModelAdmin):
    list_display = (
        "hostname", "os_family", "server_type", "in_active_directory", "in_siem",
        "dns_status", "reachability_status", "environment", "is_enabled",
        "classification_source", "updated_at",
    )
    list_filter = (
        "is_enabled", "in_active_directory", "in_siem", "os_family", "server_type",
        "classification_source", "environment", "dns_status", "reachability_status",
    )
    search_fields = (
        "hostname", "display_name", "domain", "ip_address", "application_name",
        "organizational_unit", "siem_groups", "os_name", "notes",
    )
    readonly_fields = ("created_at", "updated_at")
    actions = (enable_assets, disable_assets, reclassify_assets)
    fieldsets = (
        ("Identidad", {"fields": ("hostname", "display_name", "domain", "ip_address", "environment")}),
        (
            "Clasificación",
            {"fields": (
                "os_family", "os_name", "server_type", "application_name",
                "legacy_classification", "classification_source",
            )},
        ),
        ("Comparación de inventarios", {"fields": ("in_active_directory", "in_siem", "is_enabled")}),
        (
            "Diagnóstico de red",
            {"fields": (
                "dns_status", "resolved_fqdn", "resolved_ip_address",
                "reachability_status", "network_checked_at", "network_check_error",
                "ad_last_seen_at", "ad_last_logon_at", "siem_last_seen_at",
            )},
        ),
        (
            "Contexto del inventario anterior",
            {"fields": ("organizational_unit", "siem_groups", "inventory_source")},
        ),
        ("Contexto", {"fields": ("notes", "created_at", "updated_at")}),
    )

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if obj.classification_source == ServerAsset.CLASSIFICATION_AUTO:
            apply_automatic_classification(obj)


@admin.register(ServerNamingRule)
class ServerNamingRuleAdmin(admin.ModelAdmin):
    list_display = (
        "priority", "name", "pattern", "match_type", "os_family", "server_type", "is_active",
    )
    list_filter = ("is_active", "match_type", "os_family", "server_type")
    search_fields = ("name", "pattern", "notes")
    ordering = ("priority", "name")
    readonly_fields = ("created_at", "updated_at")
    actions = ("reclassify_with_active_rules",)

    @admin.action(description="Reclasificar todos los equipos automáticos")
    def reclassify_with_active_rules(self, request, queryset):
        updated = 0
        for asset in ServerAsset.objects.filter(
            classification_source=ServerAsset.CLASSIFICATION_AUTO,
        ):
            apply_automatic_classification(asset)
            updated += 1
        messages.success(request, f"{updated} equipo(s) reclasificado(s) con las reglas activas.")


@admin.register(ServerInventoryConfiguration)
class ServerInventoryConfigurationAdmin(admin.ModelAdmin):
    list_display = ("__str__", "ad_active_days", "retention_days", "updated_at")
    readonly_fields = ("updated_at",)

    def has_add_permission(self, request):
        return not ServerInventoryConfiguration.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(InventorySyncRun)
class InventorySyncRunAdmin(admin.ModelAdmin):
    list_display = (
        "started_at", "source", "status", "records_read", "assets_created",
        "assets_updated", "issues_count", "finished_at",
    )
    list_filter = ("source", "status")
    readonly_fields = (
        "source", "status", "started_at", "finished_at", "records_read",
        "assets_created", "assets_updated", "issues_count", "error_message", "metadata",
    )

    def has_add_permission(self, request):
        return False


@admin.register(InventoryObservation)
class InventoryObservationAdmin(admin.ModelAdmin):
    list_display = ("hostname", "source", "asset", "ip_address", "observed_at", "sync_run")
    list_filter = ("source", "sync_run")
    search_fields = ("hostname", "fqdn", "ip_address", "external_id", "organizational_unit")
    readonly_fields = (
        "sync_run", "asset", "source", "external_id", "hostname", "fqdn", "ip_address",
        "os_name", "organizational_unit", "environment", "groups", "server_type_hint",
        "observed_at", "raw_data", "created_at",
    )

    def has_add_permission(self, request):
        return False


@admin.register(AssetIdentifier)
class AssetIdentifierAdmin(admin.ModelAdmin):
    list_display = ("asset", "kind", "value", "source", "last_seen_at")
    list_filter = ("kind", "source")
    search_fields = ("asset__hostname", "value", "normalized_value")
    readonly_fields = ("normalized_value",)


@admin.register(ReconciliationIssue)
class ReconciliationIssueAdmin(admin.ModelAdmin):
    list_display = ("created_at", "issue_type", "identifier", "sync_run", "is_resolved")
    list_filter = ("issue_type", "is_resolved", "sync_run__source")
    search_fields = ("identifier", "observation__hostname")
    readonly_fields = ("sync_run", "observation", "issue_type", "identifier", "details", "created_at")
