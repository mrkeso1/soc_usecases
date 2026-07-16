from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from apps.usecases.models import UseCase


class Command(BaseCommand):
    help = "Borra todos los casos de uso del inventario, generando un backup JSON previo."

    def add_arguments(self, parser):
        parser.add_argument(
            "--yes",
            action="store_true",
            help="Confirmacion explicita para ejecutar el borrado.",
        )
        parser.add_argument(
            "--no-backup",
            action="store_true",
            help="No genera backup previo. No recomendado.",
        )

    def handle(self, *args, **options):
        if not options["yes"]:
            raise CommandError("Operacion destructiva. Ejecuta nuevamente con --yes.")

        if not options["no_backup"]:
            backup_path = self._create_backup()
            self.stdout.write(self.style.SUCCESS(f"Backup generado: {backup_path}"))

        before_count = UseCase.objects.count()
        deleted = UseCase.objects.all().delete()
        after_count = UseCase.objects.count()

        self.stdout.write(f"Casos antes: {before_count}")
        self.stdout.write(f"Resultado delete: {deleted}")
        self.stdout.write(self.style.SUCCESS(f"Casos despues: {after_count}"))

    def _create_backup(self):
        log_dir = Path(getattr(settings, "LOG_DIR", "/logs"))
        backup_dir = log_dir / "db_backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"usecases_backup_{datetime.now():%Y%m%d_%H%M%S}.json"

        call_command(
            "dumpdata",
            "usecases",
            "lifecycle",
            "sigma_tools",
            "sources.UseCaseSource",
            "controls.Control",
            indent=2,
            output=str(backup_path),
        )
        return backup_path
