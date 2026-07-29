from django.core.management.base import BaseCommand, CommandError

from apps.server_heatmap.inventory_operations import run_full_inventory_sync


class Command(BaseCommand):
    help = "Actualiza AD y SIEM, aplica filtros activos y recalcula el mapa de calor."

    def add_arguments(self, parser):
        parser.add_argument(
            "--siem-file",
            help="CSV SIEM local. Si se omite, usa SERVER_INVENTORY_SIEM_URL.",
        )

    def handle(self, *args, **options):
        try:
            result = run_full_inventory_sync(siem_file=options.get("siem_file"))
        except Exception as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                "Actualización completa finalizada. "
                f"AD: {result['ad_records']} registros. "
                f"SIEM: {result['siem_records']} registros. "
                f"Cobertura: {result['coverage_percent']}%."
            )
        )
