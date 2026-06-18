from django.core.management.base import BaseCommand, CommandError

from apps.usecases.framework_sync import run_scheduled_security_frameworks_sync


class Command(BaseCommand):
    help = (
        "Ejecuta la sincronizacion completa de frameworks: MITRE ATT&CK, "
        "D3FEND, mappings D3FEND->ATT&CK y D3FEND inferido en casos."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Ejecuta la sincronizacion aunque el intervalo configurado aun no haya vencido.",
        )
        parser.add_argument(
            "--skip-normalize",
            action="store_true",
            help="Omite normalize_d3fend_codes despues de cargar D3FEND.",
        )
        parser.add_argument(
            "--skip-usecases",
            action="store_true",
            help="Omite recalcular el D3FEND inferido en casos de uso.",
        )

    def handle(self, *args, **options):
        try:
            mitre_result = run_scheduled_security_frameworks_sync(
                force=options["force"],
                skip_normalize=options["skip_normalize"],
                skip_usecases=options["skip_usecases"],
            )
        except Exception as exc:
            raise CommandError(f"Fallo la sincronizacion completa de frameworks: {exc}") from exc

        if not mitre_result.ran:
            self.stdout.write(self.style.WARNING(mitre_result.message))
            return

        self.stdout.write(self.style.SUCCESS(mitre_result.message or "Sincronizacion MITRE finalizada."))
        self.stdout.write(f"ATT&CK creados: {mitre_result.created}")
        self.stdout.write(f"ATT&CK actualizados: {mitre_result.updated}")
        self.stdout.write(f"ATT&CK omitidos: {mitre_result.skipped}")

        self.stdout.write(self.style.SUCCESS("Sincronizacion completa de frameworks finalizada."))
