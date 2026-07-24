from django.core.management.base import BaseCommand

from apps.server_heatmap.network_diagnostics import diagnose_ingestion_gaps


class Command(BaseCommand):
    help = "Resuelve DNS y verifica conectividad de equipos AD pendientes de ingesta."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=5000)
        parser.add_argument("--workers", type=int, default=16)
        parser.add_argument("--timeout", type=float, default=2)

    def handle(self, *args, **options):
        result = diagnose_ingestion_gaps(
            limit=max(1, options["limit"]),
            workers=max(1, options["workers"]),
            timeout=max(0.5, options["timeout"]),
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Diagnóstico finalizado: {result['checked']} equipos; "
                f"{result['dns_resolved']} con DNS; {result['reachable']} responden; "
                f"{result['unreachable']} no responden; {result['errors']} sin ping disponible."
            )
        )
