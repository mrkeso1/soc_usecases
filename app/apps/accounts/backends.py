from __future__ import annotations

from typing import Optional

from django.contrib.auth.backends import BaseBackend, ModelBackend
from django.contrib.auth import get_user_model

from ldap3 import ALL, SUBTREE, Connection, Server

from .models import LDAPAuthLog, LDAPSettings


def _active_ldap_config() -> Optional[LDAPSettings]:
    return LDAPSettings.objects.filter(is_enabled=True).order_by("-updated_at").first()


def _log_ldap_event(*, event_type: str, username: str = "", config: Optional[LDAPSettings] = None, success: bool = False, message: str = "") -> None:
    LDAPAuthLog.objects.create(
        event_type=event_type,
        username=username or "",
        server_uri=config.server_uri if config else "",
        success=success,
        message=(message or "")[:2000],
    )


class AdminConfiguredLDAPBackend(BaseBackend):
    def authenticate(self, request, username: Optional[str] = None, password: Optional[str] = None, **kwargs):
        if not username or not password:
            return None

        config = _active_ldap_config()
        if not config or config.auth_mode == LDAPSettings.AUTH_MODE_LOCAL_ONLY:
            return None

        user_dn = self._resolve_user_dn(config, username)
        if not user_dn:
            _log_ldap_event(
                event_type=LDAPAuthLog.EVENT_AUTH,
                username=username,
                config=config,
                success=False,
                message="No se pudo resolver el DN del usuario.",
            )
            return None

        server = Server(config.server_uri, use_ssl=config.use_ssl, get_info=ALL)

        try:
            with Connection(server, user=user_dn, password=password, auto_bind=True) as user_conn:
                attrs = self._read_user_attributes(config, user_conn, user_dn)
        except Exception as exc:
            _log_ldap_event(
                event_type=LDAPAuthLog.EVENT_AUTH,
                username=username,
                config=config,
                success=False,
                message=str(exc),
            )
            return None

        User = get_user_model()
        user, _ = User.objects.get_or_create(username=username)
        user.ldap_dn = user_dn
        user.first_name = attrs.get(config.first_name_attr, user.first_name)
        user.last_name = attrs.get(config.last_name_attr, user.last_name)
        user.email = attrs.get(config.email_attr, user.email)
        user.display_name = attrs.get(config.display_name_attr, user.display_name)
        user.is_active = True
        user.save()
        _log_ldap_event(
            event_type=LDAPAuthLog.EVENT_AUTH,
            username=username,
            config=config,
            success=True,
            message="Autenticación LDAP exitosa.",
        )
        return user

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _resolve_user_dn(self, config: LDAPSettings, username: str) -> Optional[str]:
        if config.user_dn_template:
            return config.user_dn_template.format(username=username)

        if not (config.bind_dn and config.bind_password and config.user_search_base):
            return None

        server = Server(config.server_uri, use_ssl=config.use_ssl, get_info=ALL)
        try:
            with Connection(server, user=config.bind_dn, password=config.bind_password, auto_bind=True) as service_conn:
                search_filter = config.user_search_filter.format(username=username)
                service_conn.search(
                    search_base=config.user_search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=["distinguishedName"],
                    size_limit=1,
                )
                if not service_conn.entries:
                    return None
                return service_conn.entries[0].entry_dn
        except Exception:
            return None

    @staticmethod
    def _read_user_attributes(config: LDAPSettings, conn: Connection, user_dn: str) -> dict:
        attribute_names = [
            config.first_name_attr,
            config.last_name_attr,
            config.email_attr,
            config.display_name_attr,
        ]
        conn.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=attribute_names,
        )
        if not conn.entries:
            return {}
        entry = conn.entries[0]
        result = {}
        for attr_name in attribute_names:
            try:
                value = entry[attr_name].value
                if value:
                    result[attr_name] = str(value)
            except Exception:
                continue
        return result


class AdminControlledModelBackend(ModelBackend):
    """Local auth backend that can be disabled by LDAPSettings.auth_mode."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        user = super().authenticate(request, username=username, password=password, **kwargs)
        if user is None:
            return None

        config = _active_ldap_config()
        if (
            config
            and config.auth_mode == LDAPSettings.AUTH_MODE_LDAP_ONLY
            and not user.is_superuser
        ):
            return None
        return user
