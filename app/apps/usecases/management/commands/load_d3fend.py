import csv
import hashlib
import re
from io import StringIO

import requests
from django.core.management.base import BaseCommand

from apps.usecases.models import D3Fend, MitreAttack


D3FEND_CSV_URL = "https://d3fend.mitre.org/ontologies/d3fend/1.4.0/d3fend.csv"
D3FEND_ATTACK_MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv"

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().casefold())


def _clean_key(value: str) -> str:
    value = str(value or "").strip()

    if "#" in value:
        value = value.rsplit("#", 1)[-1]

    if "/" in value:
        value = value.rsplit("/", 1)[-1]

    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value)
    value = re.sub(r"\s+", " ", value)

    return value.strip().casefold()


def _fragment_from_uri(value: str) -> str:
    value = str(value or "").strip()

    if "#" in value:
        return value.rsplit("#", 1)[-1].strip()

    if "/" in value:
        return value.rsplit("/", 1)[-1].strip()

    return value.strip()


def _label_from_fragment(value: str) -> str:
    value = _fragment_from_uri(value)
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _code_from_label(value: str) -> str:
    value = str(value or "").strip()
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value)
    value = "".join(part[:1].upper() + part[1:] for part in value.split())
    return value.strip()


def _extract_attack_ids(row: dict) -> set[str]:
    attack_ids = set()

    for value in row.values():
        attack_ids.update(
            match.upper()
            for match in ATTACK_ID_RE.findall(str(value or ""))
        )

    return attack_ids


class Command(BaseCommand):
    help = "Carga D3FEND y sincroniza relaciones D3FEND→ATT&CK usando el CSV oficial de mappings"

    def add_arguments(self, parser):
        parser.add_argument(
            "--all",
            action="store_true",
            help="Carga todas las técnicas D3FEND. Por defecto carga solo categoría Detect.",
        )

        parser.add_argument(
            "--url",
            default=D3FEND_CSV_URL,
            help="URL del CSV oficial de D3FEND.",
        )

        parser.add_argument(
            "--skip-mappings",
            action="store_true",
            help="Carga solo técnicas D3FEND, sin sincronizar relaciones D3FEND→ATT&CK.",
        )

        parser.add_argument(
            "--mappings-only",
            action="store_true",
            help="No recarga el CSV principal; solo reconstruye mappings D3FEND→ATT&CK.",
        )

    def handle(self, *args, **options):
        if not options.get("mappings_only", False):
            self._load_d3fend_catalog(options)

        if not options.get("skip_mappings", False):
            self._load_attack_mappings()

    def _load_d3fend_catalog(self, options):
        load_all = options.get("all", False)
        url = options.get("url") or D3FEND_CSV_URL

        self.stdout.write(f"Descargando D3FEND desde: {url}")

        response = requests.get(url, timeout=120)
        response.raise_for_status()

        reader = csv.DictReader(StringIO(response.text))

        created = 0
        updated = 0
        skipped = 0
        skipped_not_detect = 0

        model_fields = self._get_d3fend_model_fields()

        for row in reader:
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

            description = (
                row.get("Description")
                or row.get("description")
                or row.get("definition")
                or row.get("Definition")
                or ""
            ).strip()

            if not code or not code.startswith("D3"):
                skipped += 1
                continue

            if not load_all and category.lower() != "detect":
                skipped_not_detect += 1
                continue

            defaults = {}

            if "name" in model_fields:
                defaults["name"] = self._fit_field("name", name or code)

            if "category" in model_fields:
                defaults["category"] = self._fit_field("category", category)

            if "description" in model_fields:
                defaults["description"] = self._fit_field("description", description)

            d3fend, was_created = D3Fend.objects.update_or_create(
                code=self._fit_field("code", code),
                defaults=defaults,
            )

            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(self.style.SUCCESS("Carga D3FEND finalizada"))
        self.stdout.write(f"Creados: {created}")
        self.stdout.write(f"Actualizados: {updated}")
        self.stdout.write(f"Omitidos por ID inválido: {skipped}")
        self.stdout.write(f"Omitidos por no ser Detect: {skipped_not_detect}")

    def _get_d3fend_model_fields(self) -> set[str]:
        return {
            field.name
            for field in D3Fend._meta.fields
        }

    def _field_max_length(self, field_name: str):
        try:
            field = D3Fend._meta.get_field(field_name)
            return field.max_length
        except Exception:
            return None

    def _fit_field(self, field_name: str, value: str) -> str:
        value = str(value or "")
        max_length = self._field_max_length(field_name)

        if max_length and len(value) > max_length:
            return value[:max_length]

        return value

    def _make_safe_code(self, code: str, label: str = "", uri: str = "") -> str:
        code = str(code or "").strip()
        code = re.sub(r"[^a-zA-Z0-9_-]+", "", code)

        if not code:
            code = _code_from_label(label)

        if not code:
            code = "D3FendMapping"

        max_length = self._field_max_length("code") or 120

        if len(code) <= max_length:
            return code

        digest = hashlib.sha1(
            str(uri or label or code).encode("utf-8")
        ).hexdigest()[:10]

        prefix_length = max_length - len(digest) - 1

        if prefix_length < 3:
            return digest[:max_length]

        return f"{code[:prefix_length]}-{digest}"

    def _add_lookup_value(self, lookup: dict, value: str, d3: D3Fend):
        if not value:
            return

        lookup[_norm(value)] = d3
        lookup[_clean_key(value)] = d3

    def _register_d3fend_in_lookup(self, lookup: dict, d3: D3Fend):
        for field in D3Fend._meta.fields:
            try:
                value = getattr(d3, field.name, None)
            except Exception:
                continue

            if isinstance(value, str) and value.strip():
                self._add_lookup_value(lookup, value, d3)

    def _build_d3fend_lookup(self) -> dict:
        lookup = {}

        for d3 in D3Fend.objects.all():
            self._register_d3fend_in_lookup(lookup, d3)

        return lookup

    def _build_attack_lookup(self) -> dict:
        return {
            attack.external_id.upper(): attack
            for attack in MitreAttack.objects
            .exclude(external_id__isnull=True)
            .exclude(external_id="")
        }

    def _resolve_attack_from_mapping_row(self, row: dict, attack_lookup: dict):
        attack_id = str(row.get("off_tech_id") or "").strip().upper()

        if attack_id:
            attack = attack_lookup.get(attack_id)

            if attack:
                return attack

        for fallback_attack_id in sorted(_extract_attack_ids(row)):
            attack = attack_lookup.get(fallback_attack_id)

            if attack:
                return attack

        return None

    def _mapping_d3fend_candidates(self, row: dict) -> list[dict]:
        candidates = []

        raw_candidates = [
            {
                "label": row.get("def_tech_label"),
                "uri": row.get("def_tech"),
                "category": row.get("def_tactic_label"),
            },
            {
                "label": row.get("top_def_tech_label"),
                "uri": None,
                "category": row.get("def_tactic_label"),
            },
            {
                "label": row.get("query_def_tech_label"),
                "uri": None,
                "category": row.get("def_tactic_label"),
            },
        ]

        seen = set()

        for item in raw_candidates:
            label = str(item.get("label") or "").strip()
            uri = str(item.get("uri") or "").strip()
            category = str(item.get("category") or "").strip()

            if not label and not uri:
                continue

            fragment = _fragment_from_uri(uri)

            if not label and fragment:
                label = _label_from_fragment(fragment)

            if not fragment:
                fragment = _code_from_label(label)

            if not fragment and not label:
                continue

            key = _clean_key(uri or label or fragment)

            if key in seen:
                continue

            seen.add(key)

            candidates.append({
                "label": label or _label_from_fragment(fragment),
                "uri": uri,
                "fragment": fragment,
                "category": category,
            })

        return candidates

    def _resolve_or_create_d3fends_from_mapping_row(self, row: dict, d3_lookup: dict):
        found = []
        created = 0
        resolved_existing = 0

        for candidate in self._mapping_d3fend_candidates(row):
            label = candidate["label"]
            uri = candidate["uri"]
            fragment = candidate["fragment"]
            category = candidate["category"]

            possible_keys = {
                _norm(label),
                _clean_key(label),
                _norm(uri),
                _clean_key(uri),
                _norm(fragment),
                _clean_key(fragment),
            }

            d3 = None

            for key in possible_keys:
                if not key:
                    continue

                d3 = d3_lookup.get(key)

                if d3:
                    break

            if d3:
                resolved_existing += 1

                if d3 not in found:
                    found.append(d3)

                continue

            code = self._make_safe_code(
                code=fragment,
                label=label,
                uri=uri,
            )

            defaults = {}
            model_fields = self._get_d3fend_model_fields()

            if "name" in model_fields:
                defaults["name"] = self._fit_field(
                    "name",
                    label or _label_from_fragment(code) or code,
                )

            if "category" in model_fields:
                defaults["category"] = self._fit_field("category", category)

            if "description" in model_fields:
                defaults["description"] = self._fit_field("description", "")

            d3, was_created = D3Fend.objects.update_or_create(
                code=self._fit_field("code", code),
                defaults=defaults,
            )

            self._register_d3fend_in_lookup(d3_lookup, d3)

            if was_created:
                created += 1
            else:
                resolved_existing += 1

            if d3 not in found:
                found.append(d3)

        return found, created, resolved_existing

    def _load_attack_mappings(self):
        if not hasattr(D3Fend, "related_attacks"):
            self.stdout.write(
                self.style.WARNING(
                    "El modelo D3Fend no tiene el campo related_attacks. "
                    "Se omite la sincronización D3FEND→ATT&CK."
                )
            )
            return

        self.stdout.write("Descargando mapeos D3FEND→ATT&CK...")

        response = requests.get(D3FEND_ATTACK_MAPPINGS_URL, timeout=120)
        response.raise_for_status()

        reader = csv.DictReader(StringIO(response.text))

        d3_lookup = self._build_d3fend_lookup()
        attack_lookup = self._build_attack_lookup()

        self.stdout.write(f"ATT&CK disponibles en DB: {len(attack_lookup)}")
        self.stdout.write(f"D3FEND disponibles antes del mapeo: {D3Fend.objects.count()}")
        self.stdout.write(f"Claves D3FEND generadas para match: {len(d3_lookup)}")

        for d3fend in D3Fend.objects.iterator():
            d3fend.related_attacks.clear()

        touched_d3fends = set()
        relation_pairs = set()

        rows_seen = 0
        linked = 0
        skipped_rows = 0
        skipped_no_attack = 0
        skipped_no_d3fend = 0
        created_from_mappings = 0
        resolved_from_mappings = 0

        sample_unmatched = []

        for row in reader:
            rows_seen += 1

            attack = self._resolve_attack_from_mapping_row(row, attack_lookup)

            if not attack:
                skipped_rows += 1
                skipped_no_attack += 1

                if len(sample_unmatched) < 5:
                    sample_unmatched.append({
                        "motivo": "ATT&CK no encontrado en DB",
                        "off_tech_id": row.get("off_tech_id"),
                        "off_tech_label": row.get("off_tech_label"),
                    })

                continue

            d3fends, created_count, resolved_count = self._resolve_or_create_d3fends_from_mapping_row(
                row=row,
                d3_lookup=d3_lookup,
            )

            created_from_mappings += created_count
            resolved_from_mappings += resolved_count

            if not d3fends:
                skipped_rows += 1
                skipped_no_d3fend += 1

                if len(sample_unmatched) < 5:
                    sample_unmatched.append({
                        "motivo": "D3FEND no encontrado ni creado",
                        "query_def_tech_label": row.get("query_def_tech_label"),
                        "top_def_tech_label": row.get("top_def_tech_label"),
                        "def_tech_label": row.get("def_tech_label"),
                        "def_tech": row.get("def_tech"),
                        "off_tech_id": row.get("off_tech_id"),
                    })

                continue

            for d3 in d3fends:
                pair = (d3.pk, attack.pk)

                if pair in relation_pairs:
                    continue

                d3.related_attacks.add(attack)

                relation_pairs.add(pair)
                touched_d3fends.add(d3.pk)
                linked += 1

        self.stdout.write(self.style.SUCCESS("Mapeos D3FEND→ATT&CK sincronizados"))
        self.stdout.write(f"Filas procesadas: {rows_seen}")
        self.stdout.write(f"Técnicas D3FEND con mapeos: {len(touched_d3fends)}")
        self.stdout.write(f"Relaciones únicas procesadas: {linked}")
        self.stdout.write(f"Filas de mapeo omitidas: {skipped_rows}")
        self.stdout.write(f"Omitidas sin ATT&CK en DB: {skipped_no_attack}")
        self.stdout.write(f"Omitidas sin D3FEND: {skipped_no_d3fend}")
        self.stdout.write(f"D3FEND creados desde mappings: {created_from_mappings}")
        self.stdout.write(f"D3FEND resueltos desde mappings: {resolved_from_mappings}")
        self.stdout.write(f"D3FEND disponibles después del mapeo: {D3Fend.objects.count()}")

        if sample_unmatched:
            self.stdout.write(
                self.style.WARNING("Muestras de filas no matcheadas:")
            )

            for sample in sample_unmatched:
                self.stdout.write(str(sample))