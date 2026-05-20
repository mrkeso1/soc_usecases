from django.core.management.base import BaseCommand

from apps.usecases.models import D3Fend, UseCase


class Command(BaseCommand):
    help = (
        "Sincroniza el D3FEND interno de cada caso de uso con las técnicas "
        "D3FEND inferidas automáticamente desde sus ATT&CK asociados."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Muestra qué casos cambiarían, sin guardar modificaciones.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        usecases = (
            UseCase.objects
            .prefetch_related("mitre_attacks", "d3fends")
            .order_by("name")
        )

        checked = 0
        changed = 0

        for usecase in usecases:
            checked += 1
            current_ids = set(usecase.d3fends.values_list("id", flat=True))
            inferred_ids = usecase.inferred_d3fend_ids()

            if current_ids == inferred_ids:
                continue

            changed += 1
            current_codes = list(
                D3Fend.objects.filter(id__in=current_ids).order_by("code").values_list("code", flat=True)
            )
            inferred_codes = list(
                D3Fend.objects.filter(id__in=inferred_ids).order_by("code").values_list("code", flat=True)
            )

            self.stdout.write(
                f"{usecase.name}: "
                f"actual=[{', '.join(current_codes) or '-'}] -> "
                f"inferido=[{', '.join(inferred_codes) or '-'}]"
            )

            if not dry_run:
                usecase.sync_d3fends_from_attacks()

        self.stdout.write("")
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY-RUN: no se guardaron cambios."))

        self.stdout.write(self.style.SUCCESS("Sincronización D3FEND finalizada."))
        self.stdout.write(f"Casos revisados: {checked}")
        self.stdout.write(f"Casos con cambios: {changed}")
