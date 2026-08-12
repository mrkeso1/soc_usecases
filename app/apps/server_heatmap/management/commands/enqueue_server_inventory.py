from django.core.management.base import BaseCommand

from apps.server_heatmap.jobs import enqueue_inventory_job
from apps.server_heatmap.models import InventoryJob


class Command(BaseCommand):
    help = "Encola una operación del inventario para el worker interno."

    def add_arguments(self, parser):
        parser.add_argument(
            "--type",
            choices=[
                InventoryJob.TYPE_FULL_SYNC,
                InventoryJob.TYPE_REPROCESS,
                InventoryJob.TYPE_APPLY_FILTERS,
                InventoryJob.TYPE_NETWORK_DIAGNOSTIC,
                InventoryJob.TYPE_SIEM_SYNC,
            ],
            default=InventoryJob.TYPE_FULL_SYNC,
        )
        parser.add_argument("--idempotency-key")

    def handle(self, *args, **options):
        job, created = enqueue_inventory_job(
            options["type"],
            idempotency_key=options.get("idempotency_key"),
        )
        state = "creado" if created else "ya existente"
        self.stdout.write(
            self.style.SUCCESS(
                f"Trabajo {state}: id={job.id}, tipo={job.job_type}, estado={job.status}."
            )
        )
