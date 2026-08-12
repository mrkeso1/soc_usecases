import os
import time

from django.core.management import BaseCommand, call_command
from django.utils import timezone

from apps.dashboard.models import MitreCoverageSnapshot


class Command(BaseCommand):
    help = "Ejecuta el scheduler persistente de sincronizacion MITRE ATT&CK/D3FEND."

    def add_arguments(self, parser):
        parser.add_argument(
            "--poll-seconds",
            type=int,
            default=None,
            help="Segundos entre evaluaciones. Por defecto usa MITRE_SYNC_POLL_SECONDS o 3600.",
        )
        parser.add_argument(
            "--once",
            action="store_true",
            help="Ejecuta una sola evaluacion y finaliza.",
        )

    def handle(self, *args, **options):
        poll_seconds = options["poll_seconds"]
        if poll_seconds is None:
            poll_seconds = int(os.getenv("MITRE_SYNC_POLL_SECONDS", "3600"))
        poll_seconds = max(60, poll_seconds)

        self.stdout.write(self.style.SUCCESS(
            f"Scheduler MITRE/D3FEND iniciado. Evaluacion cada {poll_seconds} segundos."
        ))

        while True:
            call_command("sync_security_frameworks_scheduled", stdout=self.stdout)
            if not MitreCoverageSnapshot.objects.filter(snapshot_date=timezone.localdate()).exists():
                call_command("capture_mitre_coverage_snapshot", stdout=self.stdout)
            if options["once"]:
                return
            time.sleep(poll_seconds)
