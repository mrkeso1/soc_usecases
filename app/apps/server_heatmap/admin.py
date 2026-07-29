from django.contrib import admin, messages

from .classification import apply_automatic_classification
from .models import (
    AssetIdentifier,
    InventoryFilterRule,
    InventoryObservation,
    InventoryJob,
    InventoryRuleRevision,
    InventorySyncRun,
    ReconciliationIssue,
    ServerAsset,
    ServerAssetDisableEvent,
    ServerCategory,
    ServerInventoryConfiguration,
)


@admin.register(InventoryRuleRevision)
class InventoryRuleRevisionAdmin(admin.ModelAdmin):
    list_display = (
        "created_at", "rule_type", "rule_name", "version", "action", "changed_by",
    )
    list_filter = ("rule_type", "action", "created_at")
    search_fields = ("rule_name", "changed_by__username", "request_id")
    readonly_fields = (
        "rule_type", "rule_object_id", "rule_name", "version", "action",
        "before_snapshot", "after_snapshot", "changed_fields", "changed_by",
        "request_id", "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(InventoryJob)
class InventoryJobAdmin(admin.ModelAdmin):
    list_display = (
        "created_at", "job_type", "status", "attempts", "requested_by",
        "worker_id", "heartbeat_at", "finished_at",
    )
    list_filter = ("job_type", "status", "created_at")
    search_fields = ("idempotency_key", "worker_id", "last_error", "requested_by__username")
    readonly_fields = (
        "job_type", "idempotency_key", "status", "payload", "result", "progress",
        "attempts", "max_attempts", "rerun_requested", "available_at", "started_at",
        "heartbeat_at", "lease_expires_at", "finished_at", "worker_id", "last_error",
        "requested_by", "created_at", "updated_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ServerAssetDisableEvent)
class ServerAssetDisableEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "hostname", "actor", "justification", "source_ip")
    list_filter = ("created_at",)
    search_fields = ("hostname", "actor__username", "justification", "source_ip")
    readonly_fields = (
        "asset", "hostname", "actor", "justification", "previous_enabled",
        "new_enabled", "source_ip", "user_agent", "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


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


@admin.action(description="Reaplicar reglas de inventario")
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


@admin.register(InventoryFilterRule)
class InventoryFilterRuleAdmin(admin.ModelAdmin):
    list_display = (
        "priority", "name", "source", "field", "operator", "action",
        "category", "os_family", "server_type_value", "is_active",
    )
    list_filter = ("is_active", "source", "field", "operator", "action", "os_family")
    search_fields = ("name", "pattern", "reason")
    ordering = ("priority", "name")
    readonly_fields = ("legacy_naming_rule_id", "created_at", "updated_at")


@admin.register(ServerInventoryConfiguration)
class ServerInventoryConfigurationAdmin(admin.ModelAdmin):
    list_display = (
        "__str__", "ad_active_days", "retention_days",
        "inventory_history_days", "job_history_days", "updated_at",
    )
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
