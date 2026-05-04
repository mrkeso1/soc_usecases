from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import LDAPSettings, User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Datos SOC", {"fields": ("display_name", "ldap_dn", "area")}),
    )


@admin.register(LDAPSettings)
class LDAPSettingsAdmin(admin.ModelAdmin):
    list_display = ("name", "is_enabled", "server_uri", "use_ssl", "updated_at")
    list_filter = ("is_enabled", "use_ssl")
    search_fields = ("name", "server_uri", "bind_dn", "user_search_base", "user_dn_template")
