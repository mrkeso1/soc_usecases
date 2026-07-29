from django.contrib import admin
from django.utils import timezone

from .models import ActionRateLimit, AuditLog, OperationalAlert


@admin.register(ActionRateLimit)
class ActionRateLimitAdmin(admin.ModelAdmin):
    list_display = (
        "last_request_at", "user", "scope", "request_count", "blocked_count",
        "window_started_at",
    )
    list_filter = ("scope", "last_request_at")
    search_fields = ("user__username", "scope")
    readonly_fields = (
        "user", "scope", "window_started_at", "request_count", "blocked_count",
        "last_request_at", "updated_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "entity_type", "entity_id", "actor", "ip_address")
    list_filter = ("action", "entity_type", "created_at")
    search_fields = ("action", "entity_type", "entity_id", "actor__username", "ip_address")
    readonly_fields = (
        "actor", "action", "entity_type", "entity_id", "ip_address",
        "user_agent", "details", "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(OperationalAlert)
class OperationalAlertAdmin(admin.ModelAdmin):
    list_display = (
        "last_seen_at", "severity", "status", "code", "title", "occurrences",
    )
    list_filter = ("severity", "status", "code")
    search_fields = ("code", "title", "message", "fingerprint")
    readonly_fields = (
        "code", "fingerprint", "severity", "title", "message", "context",
        "occurrences", "first_seen_at", "last_seen_at",
        "acknowledged_by", "acknowledged_at", "resolved_at",
    )
    actions = ("acknowledge_alerts", "resolve_alerts", "reopen_alerts")

    def has_add_permission(self, request):
        return False

    @admin.action(description="Reconocer alertas seleccionadas")
    def acknowledge_alerts(self, request, queryset):
        queryset.exclude(status=OperationalAlert.STATUS_RESOLVED).update(
            status=OperationalAlert.STATUS_ACKNOWLEDGED,
            acknowledged_by=request.user,
            acknowledged_at=timezone.now(),
        )

    @admin.action(description="Resolver alertas seleccionadas")
    def resolve_alerts(self, request, queryset):
        queryset.update(
            status=OperationalAlert.STATUS_RESOLVED,
            resolved_at=timezone.now(),
        )

    @admin.action(description="Reabrir alertas seleccionadas")
    def reopen_alerts(self, request, queryset):
        queryset.update(
            status=OperationalAlert.STATUS_OPEN,
            resolved_at=None,
        )
