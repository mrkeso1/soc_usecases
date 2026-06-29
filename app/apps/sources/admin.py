from django.contrib import admin

from .models import EventSource, SourceAlias, SourceCategory, SourceDeliveryMethod, SourceType, UseCaseSource


class UseCaseSourceInline(admin.TabularInline):
    model = UseCaseSource
    extra = 0
    autocomplete_fields = ["use_case"]
    fields = ["use_case", "role", "is_required", "notes", "created_by", "created_at"]
    readonly_fields = ["created_by", "created_at"]


class SourceAliasInline(admin.TabularInline):
    model = SourceAlias
    extra = 0
    fields = ["alias", "created_at"]
    readonly_fields = ["created_at"]


@admin.register(EventSource)
class EventSourceAdmin(admin.ModelAdmin):
    list_display = ["display_name", "source_type_label", "taxonomy_label", "protection", "delivery_method", "status", "updated_at"]
    list_filter = ["source_type", "protection", "delivery_method", "status", "category_ref", "subcategory_ref", "vendor", "environment"]
    search_fields = ["code", "name", "aliases__alias", "vendor", "product", "host", "owner", "category_ref__name", "subcategory_ref__name"]
    autocomplete_fields = ["category_ref", "subcategory_ref", "delivery_method"]
    readonly_fields = ["created_at", "updated_at"]
    inlines = [SourceAliasInline, UseCaseSourceInline]

    def save_model(self, request, obj, form, change):
        if not change and not obj.created_by_id:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(SourceCategory)
class SourceCategoryAdmin(admin.ModelAdmin):
    list_display = ["name", "parent", "is_active", "updated_at"]
    list_filter = ["is_active", "parent"]
    search_fields = ["name", "parent__name", "description"]
    autocomplete_fields = ["parent"]


@admin.register(SourceType)
class SourceTypeAdmin(admin.ModelAdmin):
    list_display = ["name", "code", "is_active", "updated_at"]
    list_filter = ["is_active"]
    search_fields = ["code", "name", "description"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(SourceDeliveryMethod)
class SourceDeliveryMethodAdmin(admin.ModelAdmin):
    list_display = ["name", "code", "is_active", "updated_at"]
    list_filter = ["is_active"]
    search_fields = ["code", "name", "description"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(SourceAlias)
class SourceAliasAdmin(admin.ModelAdmin):
    list_display = ["alias", "source", "created_at"]
    search_fields = ["alias", "source__code", "source__name"]
    autocomplete_fields = ["source"]
    readonly_fields = ["created_at"]


@admin.register(UseCaseSource)
class UseCaseSourceAdmin(admin.ModelAdmin):
    list_display = ["use_case", "source", "role", "is_required", "created_at"]
    list_filter = ["role", "is_required", "source__source_type", "source__status"]
    search_fields = ["use_case__name", "source__code", "source__name", "notes"]
    autocomplete_fields = ["use_case", "source"]
    readonly_fields = ["created_at"]

    def save_model(self, request, obj, form, change):
        if not change and not obj.created_by_id:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
