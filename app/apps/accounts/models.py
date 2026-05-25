from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from urllib.parse import urlparse


class User(AbstractUser):
    display_name = models.CharField(max_length=255, blank=True)
    ldap_dn = models.CharField(max_length=512, blank=True)
    area = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.display_name or self.username


class LDAPSettings(models.Model):
    AUTH_MODE_LDAP_WITH_FALLBACK = "ldap_with_fallback"
    AUTH_MODE_LDAP_ONLY = "ldap_only"
    AUTH_MODE_LOCAL_ONLY = "local_only"
    AUTH_MODE_CHOICES = [
        (AUTH_MODE_LDAP_WITH_FALLBACK, "LDAP + fallback local"),
        (AUTH_MODE_LDAP_ONLY, "Solo LDAP (superusers locales permitidos)"),
        (AUTH_MODE_LOCAL_ONLY, "Solo local"),
    ]

    name = models.CharField(max_length=100, default="LDAP Principal", unique=True)
    is_enabled = models.BooleanField(default=False)
    auth_mode = models.CharField(
        "Modo autenticación",
        max_length=32,
        choices=AUTH_MODE_CHOICES,
        default=AUTH_MODE_LDAP_WITH_FALLBACK,
    )
    server_uri = models.CharField(max_length=255, help_text="Ej: ldap://ldap.midominio.local:389")
    use_ssl = models.BooleanField(default=False)
    bind_dn = models.CharField(max_length=255, blank=True)
    bind_password = models.CharField(max_length=255, blank=True)
    user_search_base = models.CharField(max_length=255, blank=True)
    user_search_filter = models.CharField(
        max_length=255,
        default="(sAMAccountName={username})",
        help_text="Filtro LDAP. Placeholder disponible: {username}",
    )
    user_dn_template = models.CharField(
        max_length=255,
        blank=True,
        help_text="Opcional. Ej: uid={username},ou=users,dc=example,dc=com",
    )
    first_name_attr = models.CharField(max_length=100, default="givenName")
    last_name_attr = models.CharField(max_length=100, default="sn")
    email_attr = models.CharField(max_length=100, default="mail")
    display_name_attr = models.CharField(max_length=100, default="displayName")

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuración LDAP"
        verbose_name_plural = "Configuraciones LDAP"

    def __str__(self):
        return f"{self.name} ({'Activo' if self.is_enabled else 'Inactivo'})"

    def clean(self):
        super().clean()
        errors = {}
        parsed = urlparse(self.server_uri or "")

        if parsed.scheme not in {"ldap", "ldaps"} or not parsed.netloc:
            errors["server_uri"] = "Usa una URI LDAP valida, por ejemplo ldap://ldap.midominio.local:389."

        if self.use_ssl and parsed.scheme == "ldap":
            errors["use_ssl"] = "Si use_ssl esta activo, usa una URI ldaps://."

        if self.auth_mode != self.AUTH_MODE_LOCAL_ONLY:
            if "{username}" not in (self.user_dn_template or self.user_search_filter or ""):
                errors["user_search_filter"] = "Configura {username} en el filtro LDAP o en el DN template."

            if not self.user_dn_template:
                if not self.bind_dn:
                    errors["bind_dn"] = "Requerido si no usas user_dn_template."
                if not self.bind_password:
                    errors["bind_password"] = "Requerido si no usas user_dn_template."
                if not self.user_search_base:
                    errors["user_search_base"] = "Requerido si no usas user_dn_template."

        if self.is_enabled:
            qs = type(self).objects.filter(is_enabled=True)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                errors["is_enabled"] = "Ya existe una configuracion LDAP activa."

        if errors:
            raise ValidationError(errors)


class LDAPAuthLog(models.Model):
    EVENT_AUTH = "auth"
    EVENT_TEST = "test"
    EVENT_CHOICES = [
        (EVENT_AUTH, "Autenticación"),
        (EVENT_TEST, "Prueba conexión"),
    ]

    event_type = models.CharField(max_length=20, choices=EVENT_CHOICES, default=EVENT_AUTH)
    username = models.CharField(max_length=150, blank=True)
    server_uri = models.CharField(max_length=255, blank=True)
    success = models.BooleanField(default=False)
    message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Log LDAP"
        verbose_name_plural = "Logs LDAP"

    def __str__(self):
        status = "OK" if self.success else "ERROR"
        user = self.username or "-"
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.event_type} {user} {status}"
