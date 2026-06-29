from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
import re
from typing import Any, Iterable

from django.core.exceptions import ValidationError
from django.db import transaction

from apps.mitre.models import MitreAttack
from apps.sources.matching import sync_usecase_sources
from apps.usecases.models import UseCase


ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


FIELD_ALIASES = {
    "name": ("name", "nombre", "nombre_netwitness", "usecase", "use_case"),
    "group_name": ("group_name", "grupo", "group"),
    "device": ("device", "dispositivo", "platform", "fuente"),
    "case_type": ("case_type", "tipo", "type"),
    "objective": ("objective", "objetivo", "description", "descripcion"),
    "blocking_type": ("blocking_type", "tipo_bloqueo", "blocking"),
    "owner_name": ("owner_name", "responsable", "owner", "analyst"),
    "monitoring": ("monitoring", "monitoreo"),
    "status": ("status", "estado", "lifecycle_status"),
    "created_or_adjusted_at": ("created_or_adjusted_at", "fecha_alta", "created_at"),
    "production_date": ("production_date", "fecha_produccion", "production_date"),
    "severity": ("severity", "severidad"),
    "escalation": ("escalation", "escalamiento"),
    "sent_to_ho": ("sent_to_ho", "envio_ho"),
    "ho_flag": ("ho_flag", "ho"),
    "last_validation_date": ("last_validation_date", "ultima_validacion"),
    "validation_status": ("validation_status", "estado_validacion"),
    "validation_result": ("validation_result", "resultado_validacion"),
    "is_enabled": ("is_enabled", "habilitado", "enabled"),
    "disabled_reason": ("disabled_reason", "motivo_deshabilitacion"),
    "comments": ("comments", "comentarios", "notes", "notas"),
    "mitre_attack_ids": ("mitre_attack_ids", "mitre_attacks", "attack_ids", "attack"),
}


@dataclass
class InventoryRecord:
    payload: dict[str, Any]
    mitre_attack_ids: list[str] = field(default_factory=list)


@dataclass
class InventorySyncResult:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _norm_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().casefold()).strip("_")


def _first(record: dict[str, Any], aliases: Iterable[str]) -> Any:
    normalized = {_norm_key(key): value for key, value in record.items()}
    for alias in aliases:
        key = _norm_key(alias)
        if key in normalized and normalized[key] not in (None, ""):
            return normalized[key]
    return None


def _choice(value: Any, choices: list[tuple[str, str]], default: str = "") -> str:
    raw = str(value or "").strip()
    if not raw:
        return default
    folded = raw.casefold()
    for stored, label in choices:
        if folded in {str(stored).casefold(), str(label).casefold()}:
            return stored
    return raw


def _date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    raw = str(value or "").strip()
    if not raw:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


def _bool(value: Any, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "si", "s", "on", "habilitado", "enabled"}


def _attack_ids(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw = " ".join(str(item) for item in value)
    else:
        raw = str(value or "")
    return sorted({match.upper() for match in ATTACK_ID_RE.findall(raw)})


def normalize_inventory_record(record: dict[str, Any]) -> InventoryRecord:
    payload = {
        "name": str(_first(record, FIELD_ALIASES["name"]) or "").strip(),
        "group_name": str(_first(record, FIELD_ALIASES["group_name"]) or "").strip(),
        "device": str(_first(record, FIELD_ALIASES["device"]) or "").strip(),
        "case_type": str(_first(record, FIELD_ALIASES["case_type"]) or "").strip(),
        "objective": str(_first(record, FIELD_ALIASES["objective"]) or "").strip(),
        "blocking_type": _choice(_first(record, FIELD_ALIASES["blocking_type"]), UseCase.BLOCKING_TYPE_CHOICES),
        "owner_name": str(_first(record, FIELD_ALIASES["owner_name"]) or "").strip(),
        "monitoring": str(_first(record, FIELD_ALIASES["monitoring"]) or "").strip(),
        "status": _choice(
            _first(record, FIELD_ALIASES["status"]),
            UseCase.STATUS_CHOICES,
            default=UseCase.STATUS_PROPOSAL,
        ),
        "created_or_adjusted_at": _date(_first(record, FIELD_ALIASES["created_or_adjusted_at"])),
        "production_date": _date(_first(record, FIELD_ALIASES["production_date"])),
        "severity": _choice(_first(record, FIELD_ALIASES["severity"]), UseCase.SEVERITY_CHOICES),
        "escalation": _choice(_first(record, FIELD_ALIASES["escalation"]), UseCase.ESCALATION_CHOICES),
        "sent_to_ho": _choice(_first(record, FIELD_ALIASES["sent_to_ho"]), UseCase.YES_NO_CHOICES),
        "ho_flag": str(_first(record, FIELD_ALIASES["ho_flag"]) or "").strip(),
        "last_validation_date": _date(_first(record, FIELD_ALIASES["last_validation_date"])),
        "validation_status": _choice(
            _first(record, FIELD_ALIASES["validation_status"]),
            UseCase.VALIDATION_STATUS_CHOICES,
            default=UseCase.VALIDATION_STATUS_NOT_DONE,
        ),
        "validation_result": _choice(
            _first(record, FIELD_ALIASES["validation_result"]),
            UseCase.VALIDATION_RESULT_CHOICES,
            default=UseCase.VALIDATION_RESULT_NONE,
        ),
        "is_enabled": _bool(_first(record, FIELD_ALIASES["is_enabled"]), default=True),
        "disabled_reason": str(_first(record, FIELD_ALIASES["disabled_reason"]) or "").strip(),
        "comments": str(_first(record, FIELD_ALIASES["comments"]) or "").strip(),
    }
    attack_ids = _attack_ids(_first(record, FIELD_ALIASES["mitre_attack_ids"]))
    return InventoryRecord(payload=payload, mitre_attack_ids=attack_ids)


def _validation_messages(exc: ValidationError) -> list[str]:
    if hasattr(exc, "message_dict"):
        return [str(item) for messages in exc.message_dict.values() for item in messages]
    return [str(item) for item in exc.messages]


def sync_inventory_records(
    records: Iterable[dict[str, Any]],
    *,
    update_existing: bool = True,
    commit: bool = True,
    user=None,
) -> InventorySyncResult:
    with transaction.atomic():
        result = _sync_inventory_records(
            records,
            update_existing=update_existing,
            user=user,
        )
        if not commit:
            transaction.set_rollback(True)
        return result


def _sync_inventory_records(
    records: Iterable[dict[str, Any]],
    *,
    update_existing: bool,
    user=None,
) -> InventorySyncResult:
    result = InventorySyncResult()
    for index, raw_record in enumerate(records, start=1):
        record = normalize_inventory_record(raw_record)
        name = record.payload["name"]
        if not name:
            result.skipped += 1
            result.errors.append(f"Registro {index}: falta name/nombre.")
            continue

        attacks = list(MitreAttack.objects.filter(external_id__in=record.mitre_attack_ids))
        attack_ids = {attack.id for attack in attacks}
        usecase = UseCase.objects.filter(name=name).first()

        if usecase and not update_existing:
            result.skipped += 1
            continue

        if usecase is None:
            usecase = UseCase(name=name)
            usecase.created_by = user
            created = True
        else:
            created = False

        for field_name, value in record.payload.items():
            setattr(usecase, field_name, value)
        usecase.updated_by = user
        usecase._clean_mitre_attack_ids = attack_ids

        try:
            usecase.full_clean(exclude=["mitre_attacks", "d3fends"])
        except ValidationError as exc:
            result.skipped += 1
            result.errors.append(f"Registro {index} ({name}): " + "; ".join(_validation_messages(exc)))
            continue
        finally:
            try:
                delattr(usecase, "_clean_mitre_attack_ids")
            except AttributeError:
                pass

        usecase.save()
        usecase.mitre_attacks.set(attacks)
        usecase.sync_d3fends_from_attacks()
        sync_usecase_sources(
            usecase,
            record.payload.get("device"),
            create_missing=True,
            defaults={"description": "Creada automaticamente desde integracion de inventario."},
        )

        if created:
            result.created += 1
        else:
            result.updated += 1

    return result
