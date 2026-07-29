import json

from django.core.management.base import BaseCommand

from apps.server_heatmap.maintenance import maintain_server_inventory


class Command(BaseCommand):
    help = (
        "Depura históricos técnicos vencidos del inventario. "
        "Por defecto solo simula; requiere --confirm para eliminar."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--confirm",
            action="store_true",
            help="Confirma la eliminación. Sin esta opción el comando es de solo lectura.",
        )
        parser.add_argument("--inventory-days", type=int)
        parser.add_argument("--job-days", type=int)
        parser.add_argument("--resolved-alert-days", type=int)
        parser.add_argument("--rate-limit-days", type=int)

    def handle(self, *args, **options):
        result = maintain_server_inventory(
            dry_run=not options["confirm"],
            inventory_days=options["inventory_days"],
            job_days=options["job_days"],
            resolved_alert_days=options["resolved_alert_days"],
            rate_limit_days=options["rate_limit_days"],
        )
        mode = "SIMULACIÓN" if result["dry_run"] else "MANTENIMIENTO"
        self.stdout.write(f"{mode}: {json.dumps(result, ensure_ascii=False, sort_keys=True)}")
        if result["dry_run"]:
            self.stdout.write(
                "No se modificaron datos. Repetí con --confirm para aplicar la depuración."
            )
        else:
            self.stdout.write(self.style.SUCCESS("Mantenimiento finalizado."))
