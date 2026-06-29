from datetime import date

from django.core.management.base import BaseCommand, CommandError
from django.test import RequestFactory
from django.utils.dateparse import parse_date

from apps.dashboard.dashboard import build_dashboard_context, save_mitre_coverage_snapshot


class Command(BaseCommand):
    help = "Captura el estado diario de cobertura MITRE ATT&CK/D3FEND para el timeline del dashboard."

    def add_arguments(self, parser):
        parser.add_argument(
            "--date",
            dest="snapshot_date",
            help="Fecha del snapshot en formato YYYY-MM-DD. Por defecto usa hoy.",
        )

    def handle(self, *args, **options):
        snapshot_date = date.today()
        if options.get("snapshot_date"):
            parsed = parse_date(options["snapshot_date"])
            if not parsed:
                raise CommandError("La fecha debe tener formato YYYY-MM-DD.")
            snapshot_date = parsed

        request = RequestFactory().get("/dashboard/mitre/")
        request.user = None
        context = build_dashboard_context(request)
        snapshot = save_mitre_coverage_snapshot(context, snapshot_date=snapshot_date)

        self.stdout.write(
            self.style.SUCCESS(
                f"Snapshot MITRE {snapshot.snapshot_date} guardado: score {snapshot.coverage_score}%."
            )
        )
