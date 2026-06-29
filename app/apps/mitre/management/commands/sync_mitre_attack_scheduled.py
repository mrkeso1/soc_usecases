from django.core.management.base import BaseCommand, CommandError

from apps.mitre.mitre_sync import run_scheduled_mitre_attack_sync


class Command(BaseCommand):
    help = "Ejecuta la sincronizacion MITRE ATT&CK si la configuracion activa ya esta vencida."

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Ejecuta la sincronizacion aunque el intervalo configurado aun no haya vencido.",
        )

    def handle(self, *args, **options):
        try:
            result = run_scheduled_mitre_attack_sync(force=options["force"])
        except Exception as exc:
            raise CommandError(f"Fallo la sincronizacion MITRE: {exc}") from exc

        if not result.ran:
            self.stdout.write(self.style.WARNING(result.message))
            return

        self.stdout.write(self.style.SUCCESS(result.message or "Sincronizacion MITRE finalizada."))
        self.stdout.write(f"Creados: {result.created}")
        self.stdout.write(f"Actualizados: {result.updated}")
        self.stdout.write(f"Omitidos: {result.skipped}")
