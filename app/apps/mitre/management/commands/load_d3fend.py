import csv
import hashlib
import re
from io import StringIO

import requests
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.mitre.attack_ids import resolve_attack_from_lookup
from apps.mitre.models import D3Fend, D3FendAttackRelationOverride, MitreAttack


D3FEND_CSV_URL = "https://d3fend.mitre.org/ontologies/d3fend/1.4.0/d3fend.csv"
D3FEND_ATTACK_MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv"

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
D3FEND_CODE_RE = re.compile(r"\bD3-[A-Z0-9]+\b", re.IGNORECASE)


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().casefold())


def _first_value(row: dict, keys: list[str]) -> str:
    """Devuelve el primer valor no vacío de una fila, probando nombres de columna flexibles."""
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


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


def _clean_key(value: str) -> str:
    value = _label_from_fragment(value)
    return _norm(value)


def _code_from_label(value: str) -> str:
    value = str(value or "").strip()
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value)
    value = "".join(part[:1].upper() + part[1:] for part in value.split())
    return value.strip()


def _legacy_code_from_label(value: str) -> str:
    """
    Versiones anteriores del importador generaban códigos desde el label/fragment.
    Esto permite encontrar y normalizar esos registros si luego aparece el ID oficial D3-XXX.
    """
    return _code_from_label(value)


def _extract_attack_ids(row: dict) -> set[str]:
    attack_ids = set()

    for value in row.values():
        attack_ids.update(
            match.upper()
            for match in ATTACK_ID_RE.findall(str(value or ""))
        )

    return attack_ids


def _extract_d3fend_codes(row: dict) -> set[str]:
    codes = set()

    for value in row.values():
        codes.update(
            match.upper()
            for match in D3FEND_CODE_RE.findall(str(value or ""))
        )

    return codes


def _is_detect_category(value: str) -> bool:
    return str(value or "").strip().casefold() == "detect"


def _catalog_rows_from_csv(content: str) -> list[dict]:
    """
    Wrapper simple para aislar la lectura del CSV oficial.
    Si MITRE cambia levemente encabezados/columnas, las funciones extractoras se encargan.
    """
    return list(csv.DictReader(StringIO(content)))


class Command(BaseCommand):
    help = "Carga D3FEND y sincroniza relaciones D3FEND→ATT&CK usando fuentes oficiales"

    def add_arguments(self, parser):
        parser.add_argument(
            "--all",
            action="store_true",
            help="Carga todas las técnicas del CSV principal si tienen nombre/categoría válida.",
        )
        parser.add_argument(
            "--url",
            default=D3FEND_CSV_URL,
            help="URL del CSV oficial de D3FEND.",
        )
        parser.add_argument(
            "--skip-catalog",
            action="store_true",
            help="No intenta leer el CSV principal de D3FEND.",
        )
        parser.add_argument(
            "--skip-mappings",
            action="store_true",
            help="Carga solo el catálogo, sin sincronizar relaciones D3FEND→ATT&CK.",
        )
        parser.add_argument(
            "--mappings-only",
            action="store_true",
            help="No recarga el CSV principal; solo reconstruye mappings D3FEND→ATT&CK.",
        )
        parser.add_argument(
            "--disable-non-detect",
            action="store_true",
            help="Al finalizar, deshabilita D3FEND que no sean categoría Detect.",
        )

    def handle(self, *args, **options):
        if options.get("mappings_only", False):
            options["skip_catalog"] = True

        if not options.get("skip_catalog", False):
            self._load_d3fend_catalog(options)

        if not options.get("skip_mappings", False):
            self._load_attack_mappings(load_all=options.get("all", False))

        if options.get("disable_non_detect", False):
            self._disable_non_detect()

    def _get_d3fend_model_fields(self) -> set[str]:
        return {field.name for field in D3Fend._meta.fields}

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
        """
        Carga el catálogo oficial.
        Por defecto mantiene solo categoría Detect, porque es la parte aplicable al inventario SOC.
        Usar --all para conservar también hardening/deception/eviction/etc.
        """
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

            if not official_code or not official_code.upper().startswith("D3-"):
                skipped += 1
                continue

            if not name or name.upper() == official_code.upper() or not category:
                skipped += 1
                continue

            if not load_all and category.casefold() != "detect":
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
        self.stdout.write(f"Filas leídas: {len(rows)}")
        self.stdout.write(f"Creados: {created}")
        self.stdout.write(f"Actualizados: {updated}")
        self.stdout.write(f"Normalizados a código oficial: {normalized}")
        self.stdout.write(f"Omitidos por datos insuficientes: {skipped}")
        self.stdout.write(f"Omitidos por no ser Detect: {skipped_not_detect}")

    def _make_safe_code(self, code: str, label: str = "", uri: str = "") -> str:
        code = str(code or "").strip()

        official_match = D3FEND_CODE_RE.search(code) or D3FEND_CODE_RE.search(uri) or D3FEND_CODE_RE.search(label)
        if official_match:
            code = official_match.group(0).upper()
        else:
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
        self._add_lookup_value(lookup, d3.code, d3)
        self._add_lookup_value(lookup, d3.name, d3)

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

    def _excluded_relation_pairs(self) -> set[tuple[int, int]]:
        return set(
            D3FendAttackRelationOverride.objects
            .filter(action=D3FendAttackRelationOverride.ACTION_EXCLUDE)
            .values_list("d3fend_id", "attack_id")
        )

    def _resolve_attack_from_mapping_row(self, row: dict, attack_lookup: dict):
        attack_id = str(row.get("off_tech_id") or "").strip().upper()

        if attack_id:
            attack = resolve_attack_from_lookup(attack_id, attack_lookup)
            if attack:
                return attack

        for fallback_attack_id in sorted(_extract_attack_ids(row)):
            attack = resolve_attack_from_lookup(fallback_attack_id, attack_lookup)
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

        # Fallback: si el CSV cambia nombres de columna, intentamos usar cualquier valor con código D3-XXX.
        for code in sorted(_extract_d3fend_codes(row)):
            raw_candidates.append({"label": code, "uri": code, "category": row.get("def_tactic_label")})

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

    def _resolve_or_create_d3fends_from_mapping_row(self, row: dict, d3_lookup: dict, *, load_all: bool = False):
        found = []
        created = 0
        resolved_existing = 0
        skipped_not_detect = 0

        for candidate in self._mapping_d3fend_candidates(row):
            label = candidate["label"]
            uri = candidate["uri"]
            fragment = candidate["fragment"]
            category = candidate["category"]

            if not load_all and category and not _is_detect_category(category):
                skipped_not_detect += 1
                continue

            possible_keys = {
                _norm(label),
                _clean_key(label),
                _norm(uri),
                _clean_key(uri),
                _norm(fragment),
                _clean_key(fragment),
            }

            for code in _extract_d3fend_codes(candidate):
                possible_keys.add(_norm(code))
                possible_keys.add(_clean_key(code))

            d3 = None

            for key in possible_keys:
                if not key:
                    continue

                d3 = d3_lookup.get(key)
                if d3:
                    break

            if d3:
                d3_category = getattr(d3, "category", "")
                if not load_all and not _is_detect_category(category or d3_category):
                    skipped_not_detect += 1
                    continue

                resolved_existing += 1
                if d3 not in found:
                    found.append(d3)
                continue

            if not load_all and not _is_detect_category(category):
                skipped_not_detect += 1
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

        return found, created, resolved_existing, skipped_not_detect

    @transaction.atomic
    def _load_attack_mappings(self, *, load_all: bool = False):
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
        excluded_relation_pairs = self._excluded_relation_pairs()

        self.stdout.write(f"ATT&CK disponibles en DB: {len(attack_lookup)}")
        self.stdout.write(f"D3FEND disponibles antes del mapeo: {D3Fend.objects.count()}")
        self.stdout.write(f"Claves D3FEND generadas para match: {len(d3_lookup)}")
        self.stdout.write(f"Relaciones excluidas por override: {len(excluded_relation_pairs)}")

        for d3fend in D3Fend.objects.iterator():
            d3fend.related_attacks.clear()

        touched_d3fends = set()
        relation_pairs = set()

        rows_seen = 0
        linked = 0
        skipped_rows = 0
        skipped_no_attack = 0
        skipped_no_d3fend = 0
        skipped_not_detect = 0
        skipped_relation_override = 0
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

            d3fends, created_count, resolved_count, skipped_detect_count = self._resolve_or_create_d3fends_from_mapping_row(
                row=row,
                d3_lookup=d3_lookup,
                load_all=load_all,
            )

            created_from_mappings += created_count
            resolved_from_mappings += resolved_count
            skipped_not_detect += skipped_detect_count

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

                if pair in excluded_relation_pairs:
                    skipped_relation_override += 1
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
        self.stdout.write(f"D3FEND omitidos por no ser Detect: {skipped_not_detect}")
        self.stdout.write(f"Relaciones omitidas por override: {skipped_relation_override}")
        self.stdout.write(f"D3FEND creados desde mappings: {created_from_mappings}")
        self.stdout.write(f"D3FEND resueltos desde mappings: {resolved_from_mappings}")
        self.stdout.write(f"D3FEND disponibles después del mapeo: {D3Fend.objects.count()}")

        if sample_unmatched:
            self.stdout.write(self.style.WARNING("Muestras de filas no matcheadas:"))

            for sample in sample_unmatched:
                self.stdout.write(str(sample))

    def _disable_non_detect(self):
        model_fields = self._get_d3fend_model_fields()
        no_detect = D3Fend.objects.exclude(category__iexact="Detect")
        detect = D3Fend.objects.filter(category__iexact="Detect")

        if "is_enabled" not in model_fields:
            self.stdout.write(self.style.WARNING("El modelo D3Fend no tiene is_enabled. Se omite."))
            return

        disabled_values = {"is_enabled": False}
        enabled_values = {"is_enabled": True}

        if "disabled_reason" in model_fields:
            disabled_values["disabled_reason"] = (
                "Se deshabilita porque no pertenece a la categoría Detect. "
                "Se conserva en catálogo para referencia y trazabilidad."
            )
            enabled_values["disabled_reason"] = ""

        disabled_count = no_detect.update(**disabled_values)
        enabled_count = detect.update(**enabled_values)

        self.stdout.write(self.style.SUCCESS("Estado D3FEND actualizado"))
        self.stdout.write(f"D3FEND Detect habilitados: {enabled_count}")
        self.stdout.write(f"D3FEND no Detect deshabilitados: {disabled_count}")
