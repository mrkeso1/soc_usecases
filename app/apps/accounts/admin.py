import logging

from django.contrib import admin, messages
from django.contrib.auth.admin import GroupAdmin as DjangoGroupAdmin, UserAdmin as DjangoUserAdmin
from django.contrib.auth.models import Group
from django import forms
from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import redirect
from django.urls import path, reverse
from django.utils.html import format_html

from ldap3 import ALL, Connection, Server

from .ldap_utils import safe_ldap_error_message
from .models import LDAPAuthLog, LDAPSettings, User
from .roles import ROLE_GROUPS


_PASSWORD_MASK = "********"
logger = logging.getLogger("soc.auth")


class LDAPSettingsAdminForm(forms.ModelForm):
    bind_password = forms.CharField(
        label="Bind password",
        required=False,
        widget=forms.PasswordInput(
            render_value=True,
            attrs={
                "autocomplete": "new-password",
                "placeholder": "Dejar sin cambios si ya esta configurada",
            },
        ),
        help_text="Se guarda como secreto de conexion LDAP. En edicion se muestra enmascarada; escribi un valor nuevo solo si queres rotarlo.",
    )

    class Meta:
        model = LDAPSettings
        fields = "__all__"
        help_texts = {
            "is_enabled": "Solo una configuracion puede quedar activa. Tambien podes usar el boton Activar para reemplazar la actual.",
            "auth_mode": "LDAP + fallback permite usuarios locales si LDAP falla; Solo LDAP bloquea login local salvo superusuarios; Solo local ignora LDAP.",
            "server_uri": "Usa ldap://host:389 o ldaps://host:636. Si marcas use_ssl, usa ldaps://.",
            "bind_dn": "DN de cuenta de servicio para buscar usuarios, por ejemplo CN=soc-bind,OU=Services,DC=example,DC=local.",
            "user_search_base": "Base donde buscar usuarios, por ejemplo OU=Users,DC=example,DC=local.",
            "user_search_filter": "Debe incluir {username}. Ejemplo Active Directory: (sAMAccountName={username}).",
            "user_dn_template": "Opcional para bind directo. Si lo usas, tambien debe incluir {username}.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk and self.instance.bind_password:
            self.initial["bind_password"] = _PASSWORD_MASK

    def clean_bind_password(self):
        value = self.cleaned_data.get("bind_password", "")
        if (
            value == _PASSWORD_MASK
            and self.instance
            and self.instance.pk
            and self.instance.bind_password
        ):
            return self.instance.bind_password
        return value


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
    form = LDAPSettingsAdminForm
    list_display = ("name", "status_badge", "auth_mode", "server_uri", "use_ssl", "test_connection_link", "activate_link", "updated_at")
    list_filter = ("is_enabled", "auth_mode", "use_ssl")
    search_fields = ("name", "server_uri", "bind_dn", "user_search_base", "user_dn_template")
    fieldsets = (
        ("Estado", {
            "fields": ("name", "is_enabled", "auth_mode"),
            "description": "Defini si esta configuracion participa del login y como convive LDAP con usuarios locales.",
        }),
        ("Conexion", {
            "fields": ("server_uri", "use_ssl", "bind_dn", "bind_password"),
            "description": "Datos de conexion al directorio. La password queda enmascarada al editar para evitar cambios accidentales.",
        }),
        ("Busqueda de usuarios", {
            "fields": ("user_search_base", "user_search_filter", "user_dn_template"),
            "description": "Usa busqueda con cuenta de servicio o DN template. El filtro o template debe contener {username}.",
        }),
        ("Mapeo de atributos", {
            "fields": ("first_name_attr", "last_name_attr", "email_attr", "display_name_attr"),
        }),
    )

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "<int:object_id>/test-connection/",
                self.admin_site.admin_view(self.test_connection),
                name="accounts_ldapsettings_test_connection",
            ),
            path(
                "<int:object_id>/activate/",
                self.admin_site.admin_view(self.activate_config),
                name="accounts_ldapsettings_activate",
            ),
        ]
        return custom_urls + urls

    def status_badge(self, obj):
        if obj.is_enabled:
            return format_html('<strong style="color:#047857;">{}</strong>', "Activa")
        return format_html('<span style="color:#6b7280;">{}</span>', "Inactiva")
    status_badge.short_description = "Estado"

    def test_connection_link(self, obj):
        url = reverse("admin:accounts_ldapsettings_test_connection", args=[obj.pk])
        return format_html('<a class="button" href="{}">Probar conexion</a>', url)
    test_connection_link.short_description = "Prueba"

    def activate_link(self, obj):
        if obj.is_enabled:
            return format_html('<span style="color:#6b7280;">{}</span>', "Activa")
        url = reverse("admin:accounts_ldapsettings_activate", args=[obj.pk])
        return format_html('<a class="button" href="{}">Activar</a>', url)
    activate_link.short_description = "Activacion"

    def activate_config(self, request, object_id):
        config = self.get_object(request, object_id)
        if not config:
            self.message_user(request, "No se encontro la configuracion LDAP.", messages.ERROR)
            return redirect("..")

        try:
            with transaction.atomic():
                LDAPSettings.objects.filter(is_enabled=True).exclude(pk=config.pk).update(is_enabled=False)
                config.is_enabled = True
                config.full_clean()
                config.save()
        except ValidationError as exc:
            for field_errors in exc.message_dict.values():
                for error in field_errors:
                    self.message_user(request, error, messages.ERROR)
        else:
            self.message_user(
                request,
                f"'{config.name}' quedo activa y las demas configuraciones fueron desactivadas.",
                messages.SUCCESS,
            )
        return redirect("../..")

    def test_connection(self, request, object_id):
        config = self.get_object(request, object_id)
        if not config:
            self.message_user(request, "No se encontro la configuracion LDAP.", messages.ERROR)
            return redirect("..")

        success = False
        message = ""
        try:
            server = Server(config.server_uri, use_ssl=config.use_ssl, get_info=ALL)
            bind_password = config.get_bind_password()
            if config.bind_dn and bind_password:
                conn = Connection(server, user=config.bind_dn, password=bind_password, auto_bind=True)
            else:
                conn = Connection(server, auto_bind=True)
            conn.unbind()
            success = True
            message = "Conexion LDAP exitosa."
            logger.info("ldap_test_success server_uri=%s", config.server_uri)
            self.message_user(request, message, messages.SUCCESS)
        except Exception as exc:
            message = safe_ldap_error_message(exc, "Error LDAP durante prueba de conexion.")
            logger.warning("ldap_test_failed server_uri=%s message=%s", config.server_uri, message)
            self.message_user(request, f"Fallo la conexion LDAP: {message}", messages.ERROR)

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
