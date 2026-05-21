from datetime import datetime, date
from pathlib import Path
import re
import unicodedata

from django.core.management.base import BaseCommand, CommandError
from openpyxl import load_workbook

from apps.usecases.models import UseCase, MitreAttack


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
    "Severidad": "severity",
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
D3FEND_HEADERS = {"D3FEND", "D3F3ND"}


def normalize_header(value):
    return "" if value is None else str(value).strip()


def normalize_text(value):
    return "" if value is None else str(value).strip()


def normalize_key(value):
    """Clave estable para comparar valores importados sin depender de acentos o formato."""
    text = normalize_text(value).lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = re.sub(r"[\s_\-./]+", "", text)
    return text


def normalize_choice(value, choices, aliases=None):
    """
    Normaliza un valor de Excel contra los choices reales del modelo.

    Evita guardar variantes como "automatico", "semiautomatico" o "Si"
    cuando el modelo espera exactamente "Automático", "Semiautomático" o "Sí".
    Si no reconoce el valor, lo devuelve sin modificar para no ocultar datos inesperados.
    """
    text = normalize_text(value)
    if not text:
        return ""

    aliases = aliases or {}
    key = normalize_key(text)

    if key in aliases:
        return aliases[key]

    valid_values = [choice_value for choice_value, _label in choices]
    valid_by_key = {normalize_key(choice_value): choice_value for choice_value in valid_values}

    return valid_by_key.get(key, text)


def normalize_status(value):
    aliases = {
        "testing": "Test",
        "test": "Test",
        "prueba": "Test",
        "qa": "Test",
        "prod": "Producción",
        "productivo": "Producción",
        "produccion": "Producción",
        "enproduccion": "Producción",
        "desarrollo": "Desarrollo",
        "dev": "Desarrollo",
        "baja": "Baja",
        "inactivo": "Baja",
        "disabled": "Baja",
        "propuesta": "Propuesta",
        "propuesto": "Propuesta",
        "rechazado": "Propuesta",
    }
    return normalize_choice(value, UseCase.STATUS_CHOICES, aliases)


def normalize_blocking_type(value):
    aliases = {
        "aut": "Automático",
        "auto": "Automático",
        "automatico": "Automático",
        "automatizado": "Automático",
        "manual": "Manual",
        "semi": "Semiautomático",
        "semiauto": "Semiautomático",
        "semiautomatico": "Semiautomático",
    }
    return normalize_choice(value, UseCase.BLOCKING_TYPE_CHOICES, aliases)


def normalize_severity(value):
    aliases = {
        "critical": "Critical",
        "critica": "Critical",
        "critico": "Critical",
        "alta": "High",
        "alto": "High",
        "high": "High",
        "media": "Medium",
        "medio": "Medium",
        "medium": "Medium",
        "baja": "Low",
        "bajo": "Low",
        "low": "Low",
    }
    return normalize_choice(value, UseCase.SEVERITY_CHOICES, aliases)


def normalize_escalation(value):
    aliases = {
        "irt": "IRT",
        "csirt": "IRT",
        "soc": "SOC",
        "otro": "Otro",
        "otros": "Otro",
        "n/a": "Otro",
        "na": "Otro",
    }
    return normalize_choice(value, UseCase.ESCALATION_CHOICES, aliases)


def normalize_yes_no(value):
    aliases = {
        "1": "Sí",
        "si": "Sí",
        "s": "Sí",
        "yes": "Sí",
        "y": "Sí",
        "true": "Sí",
        "x": "Sí",
        "0": "No",
        "no": "No",
        "n": "No",
        "false": "No",
    }
    return normalize_choice(value, UseCase.YES_NO_CHOICES, aliases)


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


def validate_import_business_rules(payload, attack_ids):
    errors = []

    if payload.get("status") == "Producción" and not payload.get("production_date"):
        errors.append("los casos en Producción requieren Fecha puesta en producción")

    if payload.get("status") == "Producción" and not attack_ids:
        errors.append("los casos en Producción requieren al menos una técnica MITRE ATT&CK")

    validation_status = payload.get("validation_status", "")
    validation_result = payload.get("validation_result", "")
    last_validation_date = payload.get("last_validation_date")

    if validation_status == "Finalizado" and validation_result == "Nada":
        errors.append("si la validación está Finalizada, el Resultado no puede ser Nada")

    if (validation_status == "Finalizado" or validation_result in {"OK", "Advertencia", "Falló"}) and not last_validation_date:
        errors.append("las validaciones finalizadas o con resultado requieren Última validación")

    if payload.get("is_enabled") is False and not (payload.get("disabled_reason") or "").strip():
        errors.append("los casos deshabilitados requieren Motivo de deshabilitación")

    return errors


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
        ignored_d3fend_headers = [header for header in headers if header in D3FEND_HEADERS]
        if ignored_d3fend_headers:
            self.stdout.write(self.style.WARNING(
                "La columna D3FEND del Excel será ignorada: D3FEND se infiere automáticamente desde MITRE ATT&CK."
            ))

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

                for idx, field_name in mapped_indexes.items():
                    raw_value = row[idx] if idx < len(row) else None

                    if field_name == "mitre_attack_rel":
                        attack_raw = normalize_text(raw_value)
                        continue

                    if field_name in DATE_FIELDS:
                        payload[field_name] = parse_date(raw_value)
                    else:
                        payload[field_name] = normalize_text(raw_value)

                payload["status"] = normalize_status(payload.get("status", ""))
                payload["blocking_type"] = normalize_blocking_type(payload.get("blocking_type", ""))
                payload["severity"] = normalize_severity(payload.get("severity", ""))
                payload["escalation"] = normalize_escalation(payload.get("escalation", ""))
                payload["sent_to_ho"] = normalize_yes_no(payload.get("sent_to_ho", ""))
                payload["ho_flag"] = normalize_yes_no(payload.get("ho_flag", ""))

                name = payload.get("name", "").strip()
                if not name:
                    skipped_count += 1
                    self.stdout.write(self.style.WARNING(f"Fila {row_num}: omitida por no tener nombre."))
                    continue

                attack_ids = extract_attack_ids(attack_raw)
                business_errors = validate_import_business_rules(payload, attack_ids)
                if business_errors:
                    skipped_count += 1
                    self.stdout.write(self.style.WARNING(
                        f"Fila {row_num}: omitida por validación de negocio -> " + "; ".join(business_errors)
                    ))
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

                if hasattr(instance, "mitre_attacks"):
                    if allow_update:
                        instance.mitre_attacks.clear()
                    for attack_id in attack_ids:
                        attack_obj = MitreAttack.objects.filter(external_id__iexact=attack_id).first()
                        if attack_obj:
                            instance.mitre_attacks.add(attack_obj)

                instance.sync_d3fends_from_attacks()

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