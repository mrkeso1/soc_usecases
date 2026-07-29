import logging
import signal
import time

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import close_old_connections

from apps.server_heatmap.jobs import (
    claim_next_inventory_job,
    default_worker_id,
    execute_inventory_job,
    recover_zombie_jobs,
)


logger = logging.getLogger("soc.inventory")


class Command(BaseCommand):
    help = "Procesa la cola interna PostgreSQL del inventario de servidores."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Procesa como máximo un trabajo.")
        parser.add_argument("--worker-id", help="Identificador explícito del worker.")

    def handle(self, *args, **options):
        worker_id = options.get("worker_id") or default_worker_id()
        once = options["once"]
        stopping = False

        def stop(_signum, _frame):
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        self.stdout.write(f"Worker de inventario activo: {worker_id}")

        while not stopping:
            close_old_connections()
            recovered = recover_zombie_jobs()
            if recovered["recovered"] or recovered["failed"]:
                logger.warning(
                    "Se procesaron trabajos zombie.",
                    extra={"event": "inventory_jobs_recovered", "metrics": recovered},
                )
            job = claim_next_inventory_job(worker_id)
            if job:
                execute_inventory_job(job, worker_id)
                if once:
                    break
                continue
            if once:
                break
            time.sleep(settings.SERVER_INVENTORY_JOB_POLL_SECONDS)

