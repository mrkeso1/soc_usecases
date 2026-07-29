import ipaddress
import socket
from datetime import datetime, timedelta, timezone as dt_timezone
from urllib.parse import urlparse

from ldap3 import ALL, SUBTREE, Connection, Server

from .base import InventoryRecord


def _text(value):
    return str(value or "").strip()


def _ou_from_dn(dn):
    parts = [
        part[3:].strip()
        for part in _text(dn).split(",")
        if part.strip().upper().startswith("OU=")
    ]
    return " > ".join(parts)


def _environment(ou):
    normalized = ou.lower()
    return "PROD" if any(token in normalized for token in ("prod", "prd", "domain controllers")) else "LAB"


def _last_logon(value):
    raw = getattr(value, "value", value)
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=dt_timezone.utc)
    return None


def _active_computer_filter(active_days, now=None):
    enabled_computer = (
        "(&(objectCategory=computer)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    )
    if active_days <= 0:
        return f"{enabled_computer})"
    cutoff = (now or datetime.now(dt_timezone.utc)) - timedelta(days=active_days)
    # Active Directory almacena lastLogonTimestamp como intervalos de 100 ns
    # transcurridos desde el 1 de enero de 1601 UTC.
    windows_filetime = int((cutoff.timestamp() + 11644473600) * 10_000_000)
    return f"{enabled_computer}(lastLogonTimestamp>={windows_filetime}))"


def _ldap_server_address(server_uri, use_ssl):
    value = _text(server_uri)
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname
    if not host:
        raise ValueError("La dirección del servidor LDAP no es válida.")
    ssl_enabled = parsed.scheme.lower() == "ldaps" if parsed.scheme else use_ssl
    port = parsed.port or (636 if ssl_enabled else 389)
    return host, port, ssl_enabled


class ActiveDirectoryConnector:
    def __init__(
        self,
        *,
        server_uri,
        bind_user,
        bind_password,
        search_base,
        use_ssl=True,
        connect_timeout=15,
        resolve_ip=False,
        active_days=60,
    ):
        if not all((server_uri, bind_user, bind_password, search_base)):
            raise ValueError("Falta configuración obligatoria para Active Directory.")
        self.server_uri = server_uri
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.search_base = search_base
        self.use_ssl = use_ssl
        self.connect_timeout = connect_timeout
        self.resolve_ip = resolve_ip
        self.active_days = active_days

    def collect(self):
        host, port, use_ssl = _ldap_server_address(self.server_uri, self.use_ssl)
        server = Server(
            host,
            port=port,
            use_ssl=use_ssl,
            connect_timeout=self.connect_timeout,
            get_info=ALL,
        )
        connection = Connection(
            server,
            user=self.bind_user,
            password=self.bind_password,
            auto_bind=True,
            raise_exceptions=True,
        )
        try:
            connection.search(
                search_base=self.search_base,
                search_filter=_active_computer_filter(self.active_days),
                search_scope=SUBTREE,
                attributes=[
                    "cn",
                    "dNSHostName",
                    "operatingSystem",
                    "distinguishedName",
                    "memberOf",
                    "lastLogonTimestamp",
                ],
            )
            records = []
            for entry in connection.entries:
                hostname = _text(entry.cn)
                fqdn = _text(getattr(entry, "dNSHostName", "")).lower().rstrip(".")
                if not hostname and not fqdn:
                    continue
                hostname = (hostname or fqdn.split(".", 1)[0]).lower()
                ou = _ou_from_dn(entry.entry_dn)
                ip = None
                if self.resolve_ip and fqdn:
                    try:
                        ip = str(ipaddress.ip_address(socket.gethostbyname(fqdn)))
                    except (OSError, ValueError):
                        ip = None
                groups = getattr(entry, "memberOf", None)
                group_values = getattr(groups, "values", []) if groups else []
                records.append(
                    InventoryRecord(
                        external_id=fqdn or hostname,
                        hostname=hostname,
                        fqdn=fqdn,
                        ip_address=ip,
                        os_name=_text(getattr(entry, "operatingSystem", "")),
                        organizational_unit=ou,
                        environment=_environment(ou),
                        groups=", ".join(str(item) for item in group_values),
                        observed_at=_last_logon(getattr(entry, "lastLogonTimestamp", None)),
                        raw_data={
                            "distinguished_name": _text(entry.entry_dn),
                            "groups": [str(item) for item in group_values],
                        },
                    )
                )
            return records
        finally:
            connection.unbind()
