from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.server_heatmap.connectors.ad import ActiveDirectoryConnector
from apps.server_heatmap.connectors.siem import SiemCsvConnector
from apps.server_heatmap.models import InventorySyncRun
from apps.server_heatmap.reconciliation import synchronize_inventory


class Command(BaseCommand):
    help = "Sincroniza el inventario de servidores desde SIEM o Active Directory."

    def add_arguments(self, parser):
        parser.add_argument("--source", choices=("siem", "ad"), required=True)
        parser.add_argument("--file", help="CSV SIEM local. Tiene prioridad sobre SERVER_INVENTORY_SIEM_URL.")

    def handle(self, *args, **options):
        source = options["source"]
        try:
            if source == "siem":
                path = options.get("file")
                url = getattr(settings, "SERVER_INVENTORY_SIEM_URL", "")
                connector = SiemCsvConnector(
                    path=path,
                    url=None if path else url,
                    timeout=getattr(settings, "SERVER_INVENTORY_CONNECT_TIMEOUT", 30),
                )
                source_code = InventorySyncRun.SOURCE_SIEM
            else:
                connector = ActiveDirectoryConnector(
                    server_uri=getattr(settings, "SERVER_INVENTORY_AD_SERVER", ""),
                    bind_user=getattr(settings, "SERVER_INVENTORY_AD_USER", ""),
                    bind_password=getattr(settings, "SERVER_INVENTORY_AD_PASSWORD", ""),
                    search_base=getattr(settings, "SERVER_INVENTORY_AD_BASE_DN", ""),
                    use_ssl=getattr(settings, "SERVER_INVENTORY_AD_USE_SSL", True),
                    connect_timeout=getattr(settings, "SERVER_INVENTORY_CONNECT_TIMEOUT", 30),
                    resolve_ip=getattr(settings, "SERVER_INVENTORY_AD_RESOLVE_IP", False),
                )
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
