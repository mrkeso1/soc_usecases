from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import LDAPSettings
from apps.server_heatmap.connectors.ad import ActiveDirectoryConnector
from apps.server_heatmap.connectors.siem import SiemCsvConnector
from apps.server_heatmap.models import InventorySyncRun, ServerInventoryConfiguration
from apps.server_heatmap.reconciliation import synchronize_inventory


def _domain_base_from_dn(value):
    domain_parts = [
        part.strip()
        for part in (value or "").split(",")
        if part.strip().upper().startswith("DC=")
    ]
    return ",".join(domain_parts)


def build_ad_connector():
    active_days = ServerInventoryConfiguration.load().ad_active_days
    dedicated = {
        "server_uri": getattr(settings, "SERVER_INVENTORY_AD_SERVER", ""),
        "bind_user": getattr(settings, "SERVER_INVENTORY_AD_USER", ""),
        "bind_password": getattr(settings, "SERVER_INVENTORY_AD_PASSWORD", ""),
        "search_base": getattr(settings, "SERVER_INVENTORY_AD_BASE_DN", ""),
    }
    if all(dedicated.values()):
        return ActiveDirectoryConnector(
            **dedicated,
            use_ssl=getattr(settings, "SERVER_INVENTORY_AD_USE_SSL", True),
            connect_timeout=getattr(settings, "SERVER_INVENTORY_CONNECT_TIMEOUT", 30),
            resolve_ip=getattr(settings, "SERVER_INVENTORY_AD_RESOLVE_IP", False),
            active_days=active_days,
        )

    config = LDAPSettings.objects.filter(is_enabled=True).order_by("-updated_at").first()
    if not config:
        raise ValueError(
            "No hay variables de inventario AD ni una configuración LDAP activa en Admin."
        )
    bind_password = config.get_bind_password()
    search_base = (
        getattr(settings, "SERVER_INVENTORY_AD_BASE_DN", "")
        or _domain_base_from_dn(config.user_search_base)
        or _domain_base_from_dn(config.bind_dn)
    )
    if not config.bind_dn or not bind_password:
        raise ValueError(
            "La configuración LDAP activa no tiene cuenta de servicio y contraseña para consultar equipos."
        )
    if not search_base:
        raise ValueError(
            "No se pudo derivar el dominio LDAP. Configurá SERVER_INVENTORY_AD_BASE_DN."
        )
    return ActiveDirectoryConnector(
        server_uri=config.server_uri,
        bind_user=config.bind_dn,
        bind_password=bind_password,
        search_base=search_base,
        use_ssl=config.use_ssl,
        connect_timeout=getattr(settings, "SERVER_INVENTORY_CONNECT_TIMEOUT", 30),
        resolve_ip=getattr(settings, "SERVER_INVENTORY_AD_RESOLVE_IP", False),
        active_days=active_days,
    )


def build_siem_connector(*, path=None):
    url = getattr(settings, "SERVER_INVENTORY_SIEM_URL", "")
    return SiemCsvConnector(
        path=path,
        url=None if path else url,
        timeout=getattr(settings, "SERVER_INVENTORY_CONNECT_TIMEOUT", 30),
        use_environment_proxy=getattr(
            settings,
            "SERVER_INVENTORY_SIEM_USE_PROXY",
            False,
        ),
    )


class Command(BaseCommand):
    help = "Sincroniza el inventario de servidores desde SIEM o Active Directory."

    def add_arguments(self, parser):
        parser.add_argument("--source", choices=("siem", "ad"), required=True)
        parser.add_argument("--file", help="CSV SIEM local. Tiene prioridad sobre SERVER_INVENTORY_SIEM_URL.")

    def handle(self, *args, **options):
        source = options["source"]
        try:
            if source == "siem":
                connector = build_siem_connector(path=options.get("file"))
                source_code = InventorySyncRun.SOURCE_SIEM
            else:
                connector = build_ad_connector()
                source_code = InventorySyncRun.SOURCE_AD

            run = synchronize_inventory(source_code, connector)
        except (OSError, ValueError) as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Sincronización {run.get_source_display()} finalizada: "
                f"{run.records_read} registros, {run.assets_created} nuevos, "
                f"{run.assets_updated} equipos asociados y {run.issues_count} sin asociación."
            )
        )
