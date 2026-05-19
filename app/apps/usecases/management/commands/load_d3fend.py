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


HEADER_NAMES = {
    "id",
    "d3fend id",
    "d3fend_id",
    "d3fend-id",
    "code",
    "name",
    "label",
    "technique",
    "tactic",
    "category",
    "type",
    "definition",
    "description",
}


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().casefold())


def _clean_key(value: str) -> str:
    value = str(value or "").strip()

    if "#" in value:
        value = value.rsplit("#", 1)[-1]

    if "/" in value:
        value = value.rsplit("/", 1)[-1]

    value = value.replace("d3f:", "")
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value)
    value = re.sub(r"\s+", " ", value)

    return value.strip().casefold()


def _fragment_from_uri(value: str) -> str:
    value = str(value or "").strip()

    if "#" in value:
        value = value.rsplit("#", 1)[-1].strip()

    if "/" in value:
        value = value.rsplit("/", 1)[-1].strip()

    if ":" in value:
        value = value.rsplit(":", 1)[-1].strip()

    return value.strip()


def _label_from_fragment(value: str) -> str:
    value = _fragment_from_uri(value)
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _legacy_code_from_label(value: str) -> str:
    value = str(value or "").strip()
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value)
    return "".join(part[:1].upper() + part[1:] for part in value.split()).strip()


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


def _first_value(row: dict, names: list[str]) -> str:
    lower_map = {str(key or "").strip().lower(): value for key, value in row.items()}

    for name in names:
        value = lower_map.get(name.lower())
        if value not in (None, ""):
            return str(value).strip()

    return ""


def _looks_like_header(first_row: list[str]) -> bool:
    normalized = {str(value or "").strip().lower() for value in first_row}

    if normalized & HEADER_NAMES:
        return True

    first_cell = str(first_row[0] if first_row else "")
    if D3FEND_CODE_RE.search(first_cell):
        return False

    return False


def _catalog_rows_from_csv(content: str) -> list[dict]:
    """
    D3FEND publicó CSVs con más de un formato a lo largo del tiempo.
    Esta función soporta dos variantes:
      1) CSV con encabezados: ID, Tactic, Technique, Definition, etc.
      2) CSV simple sin encabezado: D3-EFA, Detect, ..., Emulated File Analysis, ..., Definition
    """
    raw_rows = list(csv.reader(StringIO(content)))

    if not raw_rows:
        return []

    first_row = raw_rows[0]

    if _looks_like_header(first_row):
        return list(csv.DictReader(StringIO(content)))

    rows = []

    for cols in raw_rows:
        if not cols:
            continue

        code = str(cols[0] if len(cols) > 0 else "").strip()

        if not D3FEND_CODE_RE.search(code):
            continue

        category = str(cols[1] if len(cols) > 1 else "").strip()

        # Formato habitual sin encabezado:
        # 0=ID, 1=Tactic, 2=Subtactic, 3=Technique, 4=Subtechnique, 5=Definition
        name = ""
        for index in (3, 4, 2):
            if len(cols) > index and str(cols[index] or "").strip():
                name = str(cols[index]).strip()
                break

        description = str(cols[5] if len(cols) > 5 else "").strip()

        rows.append({
            "ID": code,
            "Tactic": category,
            "Name": name,
            "Description": description,
        })

    return rows


class Command(BaseCommand):
    help = "Carga D3FEND con códigos oficiales D3-XXX y sincroniza relaciones inferidas D3FEND→ATT&CK."

    def add_arguments(self, parser):
        parser.add_argument(
            "--url",
            default=D3FEND_CSV_URL,
            help="URL del CSV oficial de catálogo D3FEND.",
        )
        parser.add_argument(
            "--mappings-url",
            default=D3FEND_ATTACK_MAPPINGS_URL,
            help="URL del CSV oficial de mapeos D3FEND→ATT&CK.",
        )
        parser.add_argument(
            "--all",
            action="store_true",
            help="Carga también técnicas D3FEND que no sean categoría Detect.",
        )
        parser.add_argument(
            "--skip-catalog",
            action="store_true",
            help="No recarga el catálogo; útil si solo querés reconstruir relaciones.",
        )
        parser.add_argument(
            "--skip-mappings",
            action="store_true",
            help="No sincroniza relaciones D3FEND→ATT&CK.",
        )
        parser.add_argument(
            "--mappings-only",
            action="store_true",
            help="Alias de --skip-catalog; solo reconstruye relaciones D3FEND→ATT&CK.",
        )
        parser.add_argument(
            "--disable-non-detect",
            action="store_true",
            help="Deshabilita técnicas que no pertenezcan a la categoría Detect.",
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

        for row in rows:
            official_code = self._extract_official_code(row)
            name = self._extract_name(row)
            category = self._extract_category(row)
            description = self._extract_description(row)

            if not official_code or not D3FEND_CODE_RE.fullmatch(official_code):
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
        self.stdout.write(f"Normalizados a código oficial D3-XXX: {normalized}")
        self.stdout.write(f"Omitidos por datos insuficientes: {skipped}")
        self.stdout.write(f"Omitidos por no ser Detect: {skipped_not_detect}")

    def _register_lookup_value(self, lookup: dict, value: str, d3fend: D3Fend):
        if not value:
            return

        lookup[_norm(value)] = d3fend
        lookup[_clean_key(value)] = d3fend

    def _register_d3fend(self, lookup: dict, d3fend: D3Fend):
        self._register_lookup_value(lookup, d3fend.code, d3fend)
        self._register_lookup_value(lookup, d3fend.name, d3fend)
        self._register_lookup_value(lookup, _legacy_code_from_label(d3fend.name), d3fend)

    def _build_d3fend_lookup(self) -> dict:
        lookup = {}

        for d3fend in D3Fend.objects.all():
            self._register_d3fend(lookup, d3fend)

        return lookup

    def _build_attack_lookup(self) -> dict:
        return {
            attack.external_id.upper(): attack
            for attack in MitreAttack.objects.exclude(external_id__isnull=True).exclude(external_id="")
        }

    def _resolve_attack_from_mapping_row(self, row: dict, attack_lookup: dict):
        preferred_attack_id = str(row.get("off_tech_id") or "").strip().upper()

        if preferred_attack_id and preferred_attack_id in attack_lookup:
            return attack_lookup[preferred_attack_id]

        for attack_id in sorted(_extract_attack_ids(row)):
            attack = attack_lookup.get(attack_id)
            if attack:
                return attack

        return None

    def _mapping_d3fend_candidates(self, row: dict) -> list[str]:
        values = []

        for column in [
            "def_tech_label",
            "top_def_tech_label",
            "query_def_tech_label",
            "def_tech",
            "top_def_tech",
            "query_def_tech",
        ]:
            value = str(row.get(column) or "").strip()
            if not value:
                continue

            values.append(value)
            fragment = _fragment_from_uri(value)
            if fragment:
                values.append(fragment)
                values.append(_label_from_fragment(fragment))

        for code in _extract_d3fend_codes(row):
            values.append(code)

        unique_values = []
        seen = set()

        for value in values:
            key = _clean_key(value)
            if not key or key in seen:
                continue

            seen.add(key)
            unique_values.append(value)

        return unique_values

    def _resolve_d3fends_from_mapping_row(self, row: dict, d3_lookup: dict):
        found = []
        seen_pks = set()

        for value in self._mapping_d3fend_candidates(row):
            possible_keys = {
                _norm(value),
                _clean_key(value),
                _clean_key(_label_from_fragment(value)),
                _clean_key(_legacy_code_from_label(_label_from_fragment(value))),
            }

            for key in possible_keys:
                d3fend = d3_lookup.get(key)

                if d3fend and d3fend.pk not in seen_pks:
                    found.append(d3fend)
                    seen_pks.add(d3fend.pk)

        return found

    def _load_attack_mappings(self, options):
        if not hasattr(D3Fend, "related_attacks"):
            self.stdout.write(self.style.WARNING("El modelo D3Fend no tiene related_attacks. Se omiten mapeos."))
            return

        mappings_url = options.get("mappings_url") or D3FEND_ATTACK_MAPPINGS_URL

        self.stdout.write(f"Descargando mapeos D3FEND→ATT&CK desde: {mappings_url}")

        response = requests.get(mappings_url, timeout=120)
        response.raise_for_status()

        reader = csv.DictReader(StringIO(response.text))
        d3_lookup = self._build_d3fend_lookup()
        attack_lookup = self._build_attack_lookup()

        self.stdout.write(f"ATT&CK disponibles en DB: {len(attack_lookup)}")
        self.stdout.write(f"D3FEND disponibles en DB: {D3Fend.objects.count()}")

        for d3fend in D3Fend.objects.iterator():
            d3fend.related_attacks.clear()

        relation_pairs = set()
        touched_d3fends = set()
        rows_seen = 0
        linked = 0
        skipped_no_attack = 0
        skipped_no_d3fend = 0
        sample_unmatched = []

        for row in reader:
            rows_seen += 1
            attack = self._resolve_attack_from_mapping_row(row, attack_lookup)

            if not attack:
                skipped_no_attack += 1
                if len(sample_unmatched) < 5:
                    sample_unmatched.append({
                        "motivo": "ATT&CK no encontrado en DB",
                        "off_tech_id": row.get("off_tech_id"),
                        "off_tech_label": row.get("off_tech_label"),
                    })
                continue

            d3fends = self._resolve_d3fends_from_mapping_row(row, d3_lookup)

            if not d3fends:
                skipped_no_d3fend += 1
                if len(sample_unmatched) < 5:
                    sample_unmatched.append({
                        "motivo": "D3FEND no encontrado en catálogo",
                        "def_tech_label": row.get("def_tech_label"),
                        "top_def_tech_label": row.get("top_def_tech_label"),
                        "query_def_tech_label": row.get("query_def_tech_label"),
                        "def_tech": row.get("def_tech"),
                    })
                continue

            for d3fend in d3fends:
                pair = (d3fend.pk, attack.pk)
                if pair in relation_pairs:
                    continue

                d3fend.related_attacks.add(attack)
                relation_pairs.add(pair)
                touched_d3fends.add(d3fend.pk)
                linked += 1

        self.stdout.write(self.style.SUCCESS("Mapeos D3FEND→ATT&CK sincronizados"))
        self.stdout.write(f"Filas procesadas: {rows_seen}")
        self.stdout.write(f"Técnicas D3FEND con mapeos: {len(touched_d3fends)}")
        self.stdout.write(f"Relaciones únicas procesadas: {linked}")
        self.stdout.write(f"Omitidas sin ATT&CK en DB: {skipped_no_attack}")
        self.stdout.write(f"Omitidas sin D3FEND en catálogo: {skipped_no_d3fend}")

        if sample_unmatched:
            self.stdout.write(self.style.WARNING("Muestras de filas no matcheadas:"))
            for sample in sample_unmatched:
                self.stdout.write(str(sample))

    def _disable_non_detect(self):
        model_fields = self._get_d3fend_model_fields()
        no_detect = D3Fend.objects.exclude(category__iexact="Detect")
        detect = D3Fend.objects.filter(category__iexact="Detect")

        disabled_defaults = {"is_enabled": False}
        enabled_defaults = {"is_enabled": True}

        if "disabled_reason" in model_fields:
            disabled_defaults["disabled_reason"] = (
                "Se deshabilita porque no pertenece a la categoría Detect. "
                "Se conserva en catálogo para referencia y trazabilidad."
            )
            enabled_defaults["disabled_reason"] = ""

        disabled_count = no_detect.update(**disabled_defaults)
        enabled_count = detect.update(**enabled_defaults)

        self.stdout.write(self.style.SUCCESS("Estado D3FEND actualizado"))
        self.stdout.write(f"D3FEND Detect habilitados: {enabled_count}")
        self.stdout.write(f"D3FEND no Detect deshabilitados: {disabled_count}")
