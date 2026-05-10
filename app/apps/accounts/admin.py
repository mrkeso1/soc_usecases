from django.contrib import admin, messages
from django.contrib.auth.admin import GroupAdmin as DjangoGroupAdmin, UserAdmin as DjangoUserAdmin
from django.contrib.auth.models import Group
from django.shortcuts import redirect
from django.urls import path, reverse
from django.utils.html import format_html

from ldap3 import ALL, Connection, Server

from .models import LDAPAuthLog, LDAPSettings, User
from .roles import ROLE_GROUPS


if admin.site.is_registered(Group):
    admin.site.unregister(Group)


@admin.register(Group)
class RoleGroupAdmin(DjangoGroupAdmin):
    def get_queryset(self, request):
        return super().get_queryset(request).filter(name__in=ROLE_GROUPS)

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Datos SOC", {"fields": ("display_name", "ldap_dn", "area")}),
    )

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        if db_field.name == "groups":
            kwargs["queryset"] = db_field.remote_field.model.objects.filter(name__in=ROLE_GROUPS)
        return super().formfield_for_manytomany(db_field, request, **kwargs)


@admin.register(LDAPSettings)
class LDAPSettingsAdmin(admin.ModelAdmin):
    list_display = ("name", "is_enabled", "auth_mode", "server_uri", "use_ssl", "test_connection_link", "updated_at")
    list_filter = ("is_enabled", "auth_mode", "use_ssl")
    search_fields = ("name", "server_uri", "bind_dn", "user_search_base", "user_dn_template")

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "<int:object_id>/test-connection/",
                self.admin_site.admin_view(self.test_connection),
                name="accounts_ldapsettings_test_connection",
            )
        ]
        return custom_urls + urls

    def test_connection_link(self, obj):
        url = reverse("admin:accounts_ldapsettings_test_connection", args=[obj.pk])
        return format_html('<a class="button" href="{}">Probar conexión</a>', url)
    test_connection_link.short_description = "Prueba"

    def test_connection(self, request, object_id):
        config = self.get_object(request, object_id)
        if not config:
            self.message_user(request, "No se encontró la configuración LDAP.", messages.ERROR)
            return redirect("..")

        success = False
        message = ""
        try:
            server = Server(config.server_uri, use_ssl=config.use_ssl, get_info=ALL)
            if config.bind_dn and config.bind_password:
                conn = Connection(server, user=config.bind_dn, password=config.bind_password, auto_bind=True)
            else:
                conn = Connection(server, auto_bind=True)
            conn.unbind()
            success = True
            message = "Conexión LDAP exitosa."
            self.message_user(request, message, messages.SUCCESS)
        except Exception as exc:
            message = str(exc)
            self.message_user(request, f"Falló la conexión LDAP: {message}", messages.ERROR)

        LDAPAuthLog.objects.create(
            event_type=LDAPAuthLog.EVENT_TEST,
            server_uri=config.server_uri,
            success=success,
            message=message,
        )
        return redirect("../..")


@admin.register(LDAPAuthLog)
class LDAPAuthLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "event_type", "username", "server_uri", "success", "message")
    list_filter = ("event_type", "success", "created_at")
    search_fields = ("username", "server_uri", "message")
    readonly_fields = ("event_type", "username", "server_uri", "success", "message", "created_at")
