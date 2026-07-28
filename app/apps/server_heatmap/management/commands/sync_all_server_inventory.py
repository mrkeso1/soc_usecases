from django.core.management.base import BaseCommand, CommandError

from apps.server_heatmap.inventory_filters import apply_inventory_filters
from apps.server_heatmap.management.commands.sync_server_inventory import (
    build_ad_connector,
    build_siem_connector,
)
from apps.server_heatmap.models import InventorySyncRun
from apps.server_heatmap.reconciliation import synchronize_inventory


class Command(BaseCommand):
    help = "Actualiza AD y SIEM, aplica filtros activos y recalcula el mapa de calor."

    def add_arguments(self, parser):
        parser.add_argument(
            "--siem-file",
            help="CSV SIEM local. Si se omite, usa SERVER_INVENTORY_SIEM_URL.",
        )

    def handle(self, *args, **options):
        try:
            ad_run = synchronize_inventory(
                InventorySyncRun.SOURCE_AD,
                build_ad_connector(),
                metadata={"full_sync": True},
                apply_filters_after=False,
            )
            siem_run = synchronize_inventory(
                InventorySyncRun.SOURCE_SIEM,
                build_siem_connector(path=options.get("siem_file")),
                metadata={"full_sync": True},
                apply_filters_after=False,
            )
            result = apply_inventory_filters()
        except (OSError, ValueError) as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                "Actualización completa finalizada. "
                f"AD: {ad_run.records_read} registros. "
                f"SIEM: {siem_run.records_read} registros. "
                f"Filtros: {result['processed']} observaciones evaluadas, "
                f"{result['excluded']} excluidas y "
                f"{result['classified']} equipos clasificados."
            )
        )
