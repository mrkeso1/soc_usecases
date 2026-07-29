import json
import time
import uuid

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.server_heatmap.inventory_filters import apply_inventory_filters
from apps.server_heatmap.models import (
    InventoryFilterRule,
    InventoryObservation,
    InventorySyncRun,
    ServerAsset,
)
from apps.server_heatmap.views import build_server_heatmap_context


class Command(BaseCommand):
    help = (
        "Ejecuta un benchmark reproducible del cruce, reglas y dashboard con datos "
        "sintéticos. Toda la transacción se revierte al finalizar."
    )

    def add_arguments(self, parser):
        parser.add_argument("--records", type=int, default=10_000)
        parser.add_argument("--coverage-percent", type=int, default=80)
        parser.add_argument("--lookup-sample", type=int, default=1_000)
        parser.add_argument("--max-filter-seconds", type=float, default=180)
        parser.add_argument("--max-dashboard-seconds", type=float, default=3)
        parser.add_argument("--fail-on-threshold", action="store_true")
        parser.add_argument(
            "--confirm",
            action="store_true",
            help="Obligatorio porque el benchmark genera carga temporal en PostgreSQL.",
        )

    def handle(self, *args, **options):
        if not options["confirm"]:
            raise CommandError(
                "El benchmark puede generar carga intensa. Repetí con --confirm "
                "en desarrollo o staging; no persiste datos."
            )
        total = options["records"]
        if not 10 <= total <= 100_000:
            raise CommandError("--records debe estar entre 10 y 100000.")
        coverage_percent = max(0, min(100, options["coverage_percent"]))
        covered = round(total * coverage_percent / 100)
        lookup_sample = max(0, min(total, options["lookup_sample"]))
        prefix = f"bench-{uuid.uuid4().hex[:10]}"
        now = timezone.now()

        result = {
            "records": total,
            "coverage_percent": coverage_percent,
            "lookup_sample": lookup_sample,
            "persisted": False,
        }
        started_total = time.perf_counter()
        with transaction.atomic():
            started = time.perf_counter()
            assets = ServerAsset.objects.bulk_create(
                [
                    ServerAsset(
                        hostname=f"{prefix}-{index:06d}",
                        display_name=f"{prefix}-{index:06d}",
                        os_family=(
                            ServerAsset.OS_WINDOWS
                            if index % 2 == 0
                            else ServerAsset.OS_LINUX
                        ),
                        in_active_directory=True,
                        in_siem=index < covered,
                    )
                    for index in range(total)
                ],
                batch_size=1_000,
            )
            ad_run = InventorySyncRun.objects.create(
                source=InventorySyncRun.SOURCE_AD,
                status=InventorySyncRun.STATUS_SUCCESS,
                finished_at=now,
                records_read=total,
            )
            InventoryObservation.objects.bulk_create(
                [
                    InventoryObservation(
                        sync_run=ad_run,
                        asset=asset,
                        source=InventorySyncRun.SOURCE_AD,
                        external_id=asset.hostname,
                        hostname=asset.hostname,
                        os_name=(
                            "Windows Server"
                            if index % 2 == 0
                            else "Red Hat Enterprise Linux"
                        ),
                        observed_at=now,
                    )
                    for index, asset in enumerate(assets)
                ],
                batch_size=1_000,
            )
            siem_run = InventorySyncRun.objects.create(
                source=InventorySyncRun.SOURCE_SIEM,
                status=InventorySyncRun.STATUS_SUCCESS,
                finished_at=now,
                records_read=covered,
            )
            InventoryObservation.objects.bulk_create(
                [
                    InventoryObservation(
                        sync_run=siem_run,
                        asset=assets[index],
                        source=InventorySyncRun.SOURCE_SIEM,
                        external_id=assets[index].hostname,
                        hostname=assets[index].hostname,
                        observed_at=now,
                    )
                    for index in range(covered)
                ],
                batch_size=1_000,
            )
            InventoryFilterRule.objects.create(
                name=f"Benchmark {prefix}",
                source=InventoryFilterRule.SOURCE_BOTH,
                field=InventoryFilterRule.FIELD_HOSTNAME,
                operator=InventoryFilterRule.OP_WILDCARD,
                pattern=f"{prefix}*",
                action=InventoryFilterRule.ACTION_CLASSIFY,
                os_family=ServerAsset.OS_LINUX,
                priority=1,
                is_active=True,
                reason="Regla temporal del benchmark.",
            )
            result["seed_seconds"] = round(time.perf_counter() - started, 3)

            started = time.perf_counter()
            found = 0
            for asset in assets[:lookup_sample]:
                found += int(
                    ServerAsset.objects.filter(
                        hostname__iexact=asset.hostname,
                    ).exists()
                )
            result["lookup_seconds"] = round(time.perf_counter() - started, 3)
            result["lookup_found"] = found

            started = time.perf_counter()
            filter_result = apply_inventory_filters()
            result["filter_seconds"] = round(time.perf_counter() - started, 3)
            result["filter_result"] = filter_result

            started = time.perf_counter()
            context = build_server_heatmap_context({})
            result["dashboard_seconds"] = round(time.perf_counter() - started, 3)
            result["dashboard_assets"] = context["total_assets"]

            transaction.set_rollback(True)

        result["total_seconds"] = round(time.perf_counter() - started_total, 3)
        violations = []
        if result["filter_seconds"] > options["max_filter_seconds"]:
            violations.append(
                f"reglas {result['filter_seconds']}s > {options['max_filter_seconds']}s"
            )
        if result["dashboard_seconds"] > options["max_dashboard_seconds"]:
            violations.append(
                f"dashboard {result['dashboard_seconds']}s > "
                f"{options['max_dashboard_seconds']}s"
            )
        result["threshold_violations"] = violations
        self.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if violations and options["fail_on_threshold"]:
            raise CommandError("Se excedieron umbrales: " + "; ".join(violations))
        if violations:
            self.stdout.write(self.style.WARNING("Umbrales excedidos: " + "; ".join(violations)))
        else:
            self.stdout.write(self.style.SUCCESS("Benchmark dentro de los umbrales."))
        self.stdout.write("La transacción fue revertida; no quedaron datos sintéticos.")
