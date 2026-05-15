import csv
import re
from io import StringIO

import requests
from django.core.management.base import BaseCommand

from apps.usecases.models import D3Fend, MitreAttack


D3FEND_CSV_URL = "https://d3fend.mitre.org/ontologies/d3fend/1.4.0/d3fend.csv"
D3FEND_ATTACK_MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv"
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
D3FEND_CODE_RE = re.compile(r"\bD3-[A-Z0-9]+\b", re.IGNORECASE)


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().casefold())


def _extract_attack_ids(row: dict) -> set[str]:
    attack_ids = set()
    for value in row.values():
        attack_ids.update(match.upper() for match in ATTACK_ID_RE.findall(str(value or "")))
    return attack_ids


def _extract_d3fend_codes(row: dict) -> set[str]:
    codes = set()
    for value in row.values():
        codes.update(match.upper() for match in D3FEND_CODE_RE.findall(str(value or "")))
    return codes


class Command(BaseCommand):
    help = "Carga D3FEND desde el CSV oficial y sus relaciones inferidas con ATT&CK"

    def add_arguments(self, parser):
        parser.add_argument(
            "--skip-mappings",
            action="store_true",
            help="Carga solo técnicas D3FEND, sin sincronizar relaciones D3FEND→ATT&CK.",
        )

    def handle(self, *args, **options):
        response = requests.get(D3FEND_CSV_URL, timeout=120)
        response.raise_for_status()

        content = response.text
        reader = csv.DictReader(StringIO(content))

        created = 0
        updated = 0
        skipped = 0

        for row in reader:
            # Probamos varias columnas posibles porque el CSV puede cambiar levemente
            code = (
                row.get("ID")
                or row.get("id")
                or row.get("d3fend-id")
                or row.get("d3fend_id")
                or row.get("code")
                or ""
            ).strip().upper()

            name = (
                row.get("Name")
                or row.get("name")
                or row.get("label")
                or ""
            ).strip()

            category = (
                row.get("Type")
                or row.get("type")
                or row.get("Category")
                or row.get("category")
                or ""
            ).strip()

            # Nos quedamos solo con IDs que parecen técnicas/capacidades D3FEND
            if not code or not code.startswith("D3"):
                skipped += 1
                continue

            _, was_created = D3Fend.objects.update_or_create(
                code=code,
                defaults={
                    "name": name,
                    "category": category,
                },
            )

            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(self.style.SUCCESS("Carga D3FEND finalizada"))
        self.stdout.write(f"Creados: {created}")
        self.stdout.write(f"Actualizados: {updated}")
        self.stdout.write(f"Omitidos: {skipped}")

        if not options["skip_mappings"]:
            self._load_attack_mappings()

    def _load_attack_mappings(self):
        response = requests.get(D3FEND_ATTACK_MAPPINGS_URL, timeout=120)
        response.raise_for_status()
        reader = csv.DictReader(StringIO(response.text))

        d3_by_code = {d3.code.upper(): d3 for d3 in D3Fend.objects.all()}
        d3_by_name = {_norm(d3.name): d3 for d3 in D3Fend.objects.exclude(name="")}
        attacks_by_id = {attack.external_id.upper(): attack for attack in MitreAttack.objects.all()}

        for d3fend in D3Fend.objects.iterator():
            d3fend.related_attacks.clear()

        touched_d3fends = set()
        linked = 0
        skipped_rows = 0

        for row in reader:
            attack_ids = _extract_attack_ids(row)
            d3_codes = _extract_d3fend_codes(row)
            d3fends = [d3_by_code[code] for code in d3_codes if code in d3_by_code]

            if not d3fends:
                for value in row.values():
                    d3 = d3_by_name.get(_norm(value))
                    if d3:
                        d3fends.append(d3)

            attacks = [attacks_by_id[attack_id] for attack_id in attack_ids if attack_id in attacks_by_id]
            if not d3fends or not attacks:
                skipped_rows += 1
                continue

            for d3 in d3fends:
                touched_d3fends.add(d3.pk)
                d3.related_attacks.add(*attacks)
                linked += len(attacks)

        self.stdout.write(self.style.SUCCESS("Mapeos D3FEND→ATT&CK sincronizados"))
        self.stdout.write(f"Técnicas D3FEND con mapeos: {len(touched_d3fends)}")
        self.stdout.write(f"Relaciones procesadas: {linked}")
        self.stdout.write(f"Filas de mapeo omitidas: {skipped_rows}")
