from django.core.management.base import BaseCommand

from apps.server_heatmap.network_diagnostics import diagnose_ingestion_gaps


class Command(BaseCommand):
    help = (
        "Verifica equipos AD sin SIEM que estén sin diagnóstico o deshabilitados, "
        "y deshabilita automáticamente los que no resuelven DNS o no responden al ping."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            help="Máximo de equipos. Si se omite, diagnostica todos los elegibles.",
        )
        parser.add_argument("--workers", type=int, default=16)
        parser.add_argument("--timeout", type=float, default=2)

    def handle(self, *args, **options):
        result = diagnose_ingestion_gaps(
            limit=max(1, options["limit"]) if options["limit"] else None,
            workers=max(1, options["workers"]),
            timeout=max(0.5, options["timeout"]),
            only_unchecked=True,
            include_disabled=True,
            include_covered=False,
            auto_disable_failures=True,
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Diagnóstico finalizado: {result['checked']} equipos; "
                f"{result['dns_resolved']} con DNS; {result['reachable']} responden; "
                f"{result['unreachable']} no responden; {result['errors']} sin ping disponible; "
                f"{result['disabled']} deshabilitados automáticamente."
            )
        )
