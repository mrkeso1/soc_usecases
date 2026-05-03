from datetime import datetime, date
from pathlib import Path
import re

from django.core.management.base import BaseCommand, CommandError
from openpyxl import load_workbook

from apps.usecases.models import UseCase, MitreAttack, D3Fend


COLUMN_MAP = {
    "GRUPO": "group_name",
    "DISPOSITIVO": "device",
    "TIPO": "case_type",
    "OBJETIVO2": "objective",
    "Tipo_bloqueo": "blocking_type",
    "NOMBRE NETWITNESS": "name",
    "RESPONSABLE": "owner_name",
    "Monitoreo": "monitoring",
    "status2": "status",
    "Fecha alta/ajuste": "created_or_adjusted_at",
    "Fecha puesta en producción": "production_date",
    "MITRE ATTACK": "mitre_attack_rel",
    "MITRE ATT&CK": "mitre_attack_rel",
    "D3F3ND": "d3fend_rel",
    "D3FEND": "d3fend_rel",
    "Severidad": "severity",
    "Severidad ": "severity",
    "Escalamiento": "escalation",
    "ENVIO.HO": "sent_to_ho",
    "HO": "ho_flag",
}

DATE_FIELDS = {
    "created_or_adjusted_at",
    "production_date",
    "last_review_date",
    "next_review_date",
}

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
D3FEND_ID_RE = re.compile(r"\bD3[A-Z0-9\-_.]+\b", re.IGNORECASE)


def normalize_header(value):
    return "" if value is None else str(value).strip()


def normalize_text(value):
    return "" if value is None else str(value).strip()


def normalize_status(value):
    text = normalize_text(value)
    mapping = {
        "testing": "Test",
        "test": "Test",
        "produccion": "Producción",
        "producción": "Producción",
        "desarrollo": "Desarrollo",
        "baja": "Baja",
        "propuesta": "Propuesta",
        "rechazado": "Propuesta",
    }
    return mapping.get(text.lower(), text)


def normalize_blocking_type(value):
    text = normalize_text(value)
    mapping = {
        "aut": "automatico",
        "automatico": "automatico",
        "automático": "automatico",
        "manual": "manual",
        "semi": "semiautomatico",
        "semiautomatico": "semiautomatico",
        "semiautomático": "semiautomatico",
    }
    return mapping.get(text.lower(), text)


def normalize_severity(value):
    text = normalize_text(value)
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    return mapping.get(text.lower(), text)


def normalize_yes_no(value):
    text = normalize_text(value)
    mapping = {
        "1": "Si",
        "si": "Si",
        "sí": "Si",
        "s": "Si",
        "true": "Si",
        "0": "No",
        "no": "No",
        "n": "No",
        "false": "No",
    }
    return mapping.get(text.lower(), text)


def parse_date(value):
    if value in (None, ""):
        return None

    if isinstance(value, date):
        return value if not isinstance(value, datetime) else value.date()

    text = str(value).strip()
    if not text:
        return None

    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue

    return None


def extract_attack_ids(value):
    if not value:
        return []
    found = ATTACK_ID_RE.findall(str(value))
    return sorted(set(item.upper() for item in found))


def extract_d3fend_codes(value):
    if not value:
        return []
    text = str(value).replace(",", ";")
    codes = []

    regex_found = D3FEND_ID_RE.findall(text)
    if regex_found:
        codes.extend(regex_found)

    if not codes:
        parts = [p.strip() for p in text.split(";") if p and p.strip()]
        codes.extend(parts)

    return sorted(set(item.upper() for item in codes))


class Command(BaseCommand):
    help = "Importa casos de uso desde un archivo Excel"

    def add_arguments(self, parser):
        parser.add_argument("excel_path", type=str, help="Ruta al archivo Excel")
        parser.add_argument("--sheet", type=str, default=None, help="Nombre de la hoja")
        parser.add_argument(
            "--update",
            action="store_true",
            help="Actualiza registros existentes si encuentra el mismo nombre",
        )

    def handle(self, *args, **options):
        excel_path = Path(options["excel_path"])
        sheet_name = options["sheet"]
        allow_update = options["update"]

        if not excel_path.exists():
            raise CommandError(f"No existe el archivo: {excel_path}")

        wb = load_workbook(excel_path, data_only=True)

        if sheet_name:
            if sheet_name not in wb.sheetnames:
                raise CommandError(
                    f"La hoja '{sheet_name}' no existe. Hojas disponibles: {', '.join(wb.sheetnames)}"
                )
            ws = wb[sheet_name]
        else:
            ws = wb[wb.sheetnames[0]]

        rows = list(ws.iter_rows(values_only=True))
        if not rows:
            raise CommandError("La hoja está vacía.")

        headers = [normalize_header(h) for h in rows[0]]
        mapped_indexes = {}

        for idx, header in enumerate(headers):
            if header in COLUMN_MAP:
                mapped_indexes[idx] = COLUMN_MAP[header]

        if "name" not in mapped_indexes.values():
            raise CommandError("No se encontró la columna 'NOMBRE NETWITNESS'.")

        created_count = 0
        updated_count = 0
        skipped_count = 0
        error_count = 0

        for row_num, row in enumerate(rows[1:], start=2):
            try:
                payload = {}
                attack_raw = ""
                d3fend_raw = ""

                for idx, field_name in mapped_indexes.items():
                    raw_value = row[idx] if idx < len(row) else None

                    if field_name == "mitre_attack_rel":
                        attack_raw = normalize_text(raw_value)
                        continue

                    if field_name == "d3fend_rel":
                        d3fend_raw = normalize_text(raw_value)
                        continue

                    if field_name in DATE_FIELDS:
                        payload[field_name] = parse_date(raw_value)
                    else:
                        payload[field_name] = normalize_text(raw_value)

                payload["status"] = normalize_status(payload.get("status", ""))
                payload["blocking_type"] = normalize_blocking_type(payload.get("blocking_type", ""))
                payload["severity"] = normalize_severity(payload.get("severity", ""))
                payload["sent_to_ho"] = normalize_yes_no(payload.get("sent_to_ho", ""))
                payload["ho_flag"] = normalize_yes_no(payload.get("ho_flag", ""))

                name = payload.get("name", "").strip()
                if not name:
                    skipped_count += 1
                    self.stdout.write(self.style.WARNING(f"Fila {row_num}: omitida por no tener nombre."))
                    continue

                instance = UseCase.objects.filter(name=name).first()

                if instance:
                    if not allow_update:
                        skipped_count += 1
                        self.stdout.write(self.style.WARNING(f"Fila {row_num}: ya existe '{name}', omitido."))
                        continue

                    for field, value in payload.items():
                        setattr(instance, field, value)
                    instance.save()
                    action = "actualizado"
                    updated_count += 1
                else:
                    instance = UseCase.objects.create(**payload)
                    action = "creado"
                    created_count += 1

                attack_ids = extract_attack_ids(attack_raw)
                d3fend_codes = extract_d3fend_codes(d3fend_raw)

                if hasattr(instance, "mitre_attacks"):
                    if allow_update:
                        instance.mitre_attacks.clear()
                    for attack_id in attack_ids:
                        attack_obj = MitreAttack.objects.filter(external_id__iexact=attack_id).first()
                        if attack_obj:
                            instance.mitre_attacks.add(attack_obj)

                if hasattr(instance, "d3fends"):
                    if allow_update:
                        instance.d3fends.clear()
                    for code in d3fend_codes:
                        d3fend_obj = D3Fend.objects.filter(code__iexact=code).first()
                        if d3fend_obj:
                            instance.d3fends.add(d3fend_obj)

                self.stdout.write(self.style.SUCCESS(f"Fila {row_num}: {action} '{name}'"))

            except Exception as exc:
                error_count += 1
                self.stdout.write(self.style.ERROR(f"Fila {row_num}: error -> {exc}"))

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("Importación finalizada"))
        self.stdout.write(f"Creados: {created_count}")
        self.stdout.write(f"Actualizados: {updated_count}")
        self.stdout.write(f"Omitidos: {skipped_count}")
        self.stdout.write(f"Errores: {error_count}")