import csv
import re
from io import StringIO

import requests
from django.core.management.base import BaseCommand
from django.db import transaction

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
        if options.get("mappings_only"):
            options["skip_catalog"] = True

        if not options.get("skip_catalog"):
            self._load_d3fend_catalog(options)

        if not options.get("skip_mappings"):
            self._load_attack_mappings(options)

        if options.get("disable_non_detect"):
            self._disable_non_detect()

    def _get_d3fend_model_fields(self) -> set[str]:
        return {field.name for field in D3Fend._meta.fields}

    def _field_max_length(self, field_name: str):
        try:
            return D3Fend._meta.get_field(field_name).max_length
        except Exception:
            return None

    def _fit_field(self, field_name: str, value: str) -> str:
        value = str(value or "")
        max_length = self._field_max_length(field_name)

        if max_length and len(value) > max_length:
            return value[:max_length]

        return value

    def _extract_official_code(self, row: dict) -> str:
        preferred_columns = [
            "ID",
            "id",
            "D3FEND ID",
            "D3FEND_ID",
            "d3fend-id",
            "d3fend_id",
            "code",
            "Code",
        ]

        for column in preferred_columns:
            value = str(row.get(column, "") or "")
            match = D3FEND_CODE_RE.search(value)
            if match:
                return match.group(0).upper()

        for value in row.values():
            match = D3FEND_CODE_RE.search(str(value or ""))
            if match:
                return match.group(0).upper()

        return ""

    def _extract_name(self, row: dict) -> str:
        name = _first_value(row, [
            "Name",
            "name",
            "Technique",
            "technique",
            "D3FEND Technique",
            "D3FEND Technique Name",
            "label",
            "Label",
            "def_tech_label",
            "top_def_tech_label",
            "query_def_tech_label",
        ])

        if name:
            return name

        for key in ("URI", "uri", "URL", "url", "def_tech"):
            value = str(row.get(key, "") or "")
            if value:
                label = _label_from_fragment(value)
                if label:
                    return label

        return ""

    def _extract_category(self, row: dict) -> str:
        return _first_value(row, [
            "Tactic",
            "tactic",
            "Category",
            "category",
            "Type",
            "type",
            "def_tactic_label",
        ])

    def _extract_description(self, row: dict) -> str:
        return _first_value(row, [
            "Description",
            "description",
            "Definition",
            "definition",
            "Definición",
            "definicion",
        ])

    def _merge_records(self, source: D3Fend, target: D3Fend):
        if source.pk == target.pk:
            return target

        if hasattr(target, "related_attacks"):
            target.related_attacks.add(*source.related_attacks.all())

        if hasattr(target, "use_cases"):
            target.use_cases.add(*source.use_cases.all())

        source.delete()
        return target

    def _find_existing_for_catalog_row(self, official_code: str, name: str):
        by_code = D3Fend.objects.filter(code__iexact=official_code).first()
        candidates = []

        if name:
            candidates.append(D3Fend.objects.filter(name__iexact=name).first())
            legacy_code = _legacy_code_from_label(name)
            if legacy_code:
                candidates.append(D3Fend.objects.filter(code__iexact=legacy_code).first())

        for candidate in candidates:
            if not candidate:
                continue

            if by_code and by_code.pk != candidate.pk:
                return self._merge_records(candidate, by_code), False

            return candidate, False

        if by_code:
            return by_code, False

        return None, True

    @transaction.atomic
    def _upsert_d3fend(self, official_code: str, name: str, category: str, description: str):
        model_fields = self._get_d3fend_model_fields()
        d3fend, should_create = self._find_existing_for_catalog_row(official_code, name)

        defaults = {}
        if "name" in model_fields:
            defaults["name"] = self._fit_field("name", name)
        if "category" in model_fields:
            defaults["category"] = self._fit_field("category", category)
        if "description" in model_fields:
            defaults["description"] = self._fit_field("description", description)

        if should_create or not d3fend:
            d3fend = D3Fend.objects.create(
                code=self._fit_field("code", official_code),
                **defaults,
            )
            return d3fend, True

        changed = False

        if d3fend.code.upper() != official_code.upper():
            d3fend.code = self._fit_field("code", official_code)
            changed = True

        for field, value in defaults.items():
            if getattr(d3fend, field, None) != value:
                setattr(d3fend, field, value)
                changed = True

        if changed:
            d3fend.save()

        return d3fend, False

    def _load_d3fend_catalog(self, options):
        load_all = options.get("all", False)
        url = options.get("url") or D3FEND_CSV_URL

        self.stdout.write(f"Descargando catálogo D3FEND desde: {url}")

        response = requests.get(url, timeout=120)
        response.raise_for_status()

        rows = _catalog_rows_from_csv(response.text)

        created = 0
        updated = 0
        skipped = 0
        skipped_not_detect = 0
        normalized = 0

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

            if not name or name.upper() == official_code.upper() or not category:
                skipped += 1
                continue

            if not load_all and category.lower() != "detect":
                skipped_not_detect += 1
                continue

            old_match = D3Fend.objects.filter(name__iexact=name).first()
            old_code = old_match.code if old_match else ""

            _, was_created = self._upsert_d3fend(
                official_code=official_code,
                name=name,
                category=category,
                description=description,
            )

            if was_created:
                created += 1
            else:
                updated += 1
                if old_code and old_code.upper() != official_code.upper():
                    normalized += 1

        self.stdout.write(self.style.SUCCESS("Carga catálogo D3FEND finalizada"))
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
