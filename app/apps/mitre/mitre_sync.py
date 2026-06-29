"""MITRE ATT&CK catalog synchronization helpers."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Callable

import requests
from django.utils import timezone

from .models import MitreAttack, MitreAttackSyncSettings


ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
logger = logging.getLogger("soc.mitre_sync")


@dataclass(frozen=True)
class MitreAttackSyncResult:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    total: int = 0
    ran: bool = True
    message: str = ""


def fetch_mitre_attack_enterprise(url: str = ATTACK_ENTERPRISE_URL, timeout: int = 120) -> dict:
    logger.info("mitre_fetch_start url=%s timeout=%s", url, timeout)
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    logger.info("mitre_fetch_success url=%s status_code=%s", url, response.status_code)
    return response.json()


def load_mitre_attack_data(data: dict) -> MitreAttackSyncResult:
    created = 0
    updated = 0
    skipped = 0

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue

        attack_id = _attack_external_id(obj)
        if not attack_id:
            skipped += 1
            continue

        _, was_created = MitreAttack.objects.update_or_create(
            external_id=attack_id,
            defaults={
                "name": obj.get("name", "").strip(),
                "tactic": _attack_tactics(obj),
            },
        )
        if was_created:
            created += 1
        else:
            updated += 1

    result = MitreAttackSyncResult(
        created=created,
        updated=updated,
        skipped=skipped,
        total=created + updated,
        message="Carga ATT&CK finalizada.",
    )
    logger.info(
        "mitre_load_finished created=%s updated=%s skipped=%s total=%s",
        result.created,
        result.updated,
        result.skipped,
        result.total,
    )
    return result


def run_scheduled_mitre_attack_sync(
    *,
    force: bool = False,
    settings: MitreAttackSyncSettings | None = None,
    fetcher: Callable[[], dict] = fetch_mitre_attack_enterprise,
    now=None,
) -> MitreAttackSyncResult:
    settings = settings or MitreAttackSyncSettings.get_active()
    if not settings:
        message = "No hay configuracion activa de sincronizacion MITRE."
        logger.warning("mitre_sync_skipped reason=%s", message)
        return MitreAttackSyncResult(ran=False, message=message)

    now = now or timezone.now()
    if not force and not settings.is_due(now):
        next_run = settings.next_run_at()
        message = "Sincronizacion MITRE omitida: aun no corresponde ejecutar."
        if next_run:
            message = f"{message} Próxima ejecución: {timezone.localtime(next_run):%Y-%m-%d %H:%M}."
        logger.info("mitre_sync_skipped settings=%s message=%s", settings.name, message)
        return MitreAttackSyncResult(ran=False, message=message)

    logger.info("mitre_sync_start settings=%s force=%s", settings.name, force)
    settings.mark_running(now)
    try:
        result = load_mitre_attack_data(fetcher())
    except Exception as exc:
        settings.mark_error(str(exc), now)
        logger.exception("mitre_sync_failed settings=%s error=%s", settings.name, exc)
        raise

    settings.mark_success(result, now)
    logger.info(
        "mitre_sync_success settings=%s created=%s updated=%s skipped=%s",
        settings.name,
        result.created,
        result.updated,
        result.skipped,
    )
    return result


def _attack_external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return (ref.get("external_id") or "").strip()
    return ""


def _attack_tactics(obj: dict) -> str:
    tactic_names = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactic_names.append(phase.get("phase_name", "").replace("-", " ").title())
    return ", ".join(sorted(set(filter(None, tactic_names))))
