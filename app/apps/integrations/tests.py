from datetime import date
import json
from io import StringIO
from pathlib import Path
import tempfile

from django.core.management import call_command
from django.test import TestCase

from apps.integrations.inventory import normalize_inventory_record, sync_inventory_records
from apps.mitre.models import MitreAttack
from apps.usecases.models import UseCase


class InventoryIntegrationTests(TestCase):
    def test_normalize_inventory_record_accepts_external_aliases(self):
        record = normalize_inventory_record({
            "nombre": "External brute force",
            "dispositivo": "SIEM",
            "estado": UseCase.STATUS_PRODUCTION,
            "fecha_produccion": "2026-01-02",
            "attack_ids": "T1110 - Brute Force",
            "habilitado": "si",
        })

        self.assertEqual(record.payload["name"], "External brute force")
        self.assertEqual(record.payload["device"], "SIEM")
        self.assertEqual(record.payload["production_date"], date(2026, 1, 2))
        self.assertEqual(record.mitre_attack_ids, ["T1110"])

    def test_sync_inventory_records_creates_usecase_and_attack_mapping(self):
        attack = MitreAttack.objects.create(external_id="T1110", name="Brute Force")

        result = sync_inventory_records([
            {
                "name": "External brute force",
                "status": UseCase.STATUS_PRODUCTION,
                "production_date": "2026-01-02",
                "mitre_attack_ids": ["T1110"],
                "severity": "High",
            }
        ])

        self.assertTrue(result.ok)
        self.assertEqual(result.created, 1)
        usecase = UseCase.objects.get(name="External brute force")
        self.assertEqual(usecase.status, UseCase.STATUS_PRODUCTION)
        self.assertEqual(list(usecase.mitre_attacks.all()), [attack])

    def test_sync_inventory_records_rejects_production_without_loaded_attack(self):
        result = sync_inventory_records([
            {
                "name": "External unmapped",
                "status": UseCase.STATUS_PRODUCTION,
                "production_date": "2026-01-02",
            }
        ])

        self.assertFalse(result.ok)
        self.assertEqual(result.skipped, 1)
        self.assertFalse(UseCase.objects.filter(name="External unmapped").exists())

    def test_sync_inventory_records_dry_run_does_not_persist(self):
        MitreAttack.objects.create(external_id="T1110", name="Brute Force")

        result = sync_inventory_records([
            {
                "name": "External dry run",
                "status": UseCase.STATUS_PRODUCTION,
                "production_date": "2026-01-02",
                "mitre_attack_ids": "T1110",
            }
        ], commit=False)

        self.assertTrue(result.ok)
        self.assertEqual(result.created, 1)
        self.assertFalse(UseCase.objects.filter(name="External dry run").exists())


class ImportExternalInventoryCommandTests(TestCase):
    def test_command_imports_json_records(self):
        MitreAttack.objects.create(external_id="T1110", name="Brute Force")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "inventory.json"
            path.write_text(json.dumps([
                {
                    "nombre": "External JSON case",
                    "estado": UseCase.STATUS_PRODUCTION,
                    "fecha_produccion": "2026-01-02",
                    "attack_ids": "T1110",
                }
            ]), encoding="utf-8")

            call_command("import_external_inventory", str(path), stdout=StringIO(), verbosity=0)

        self.assertTrue(UseCase.objects.filter(name="External JSON case").exists())

    def test_command_imports_csv_records(self):
        MitreAttack.objects.create(external_id="T1110", name="Brute Force")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "inventory.csv"
            path.write_text(
                "nombre,estado,fecha_produccion,attack_ids\n"
                f"External CSV case,{UseCase.STATUS_PRODUCTION},2026-01-02,T1110\n",
                encoding="utf-8",
            )

            call_command("import_external_inventory", str(path), stdout=StringIO(), verbosity=0)

        self.assertTrue(UseCase.objects.filter(name="External CSV case").exists())
