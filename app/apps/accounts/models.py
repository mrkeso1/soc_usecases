from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    display_name = models.CharField(max_length=255, blank=True)
    ldap_dn = models.CharField(max_length=512, blank=True)
    area = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.display_name or self.username


class LDAPSettings(models.Model):
    name = models.CharField(max_length=100, default="LDAP Principal", unique=True)
    is_enabled = models.BooleanField(default=False)
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
