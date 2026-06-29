"""Full security framework synchronization helpers."""

from __future__ import annotations

from io import StringIO
import logging
import re

from django.core.management import call_command

from .mitre_sync import MitreAttackSyncResult, run_scheduled_mitre_attack_sync
from .models import D3Fend, MitreAttack, MitreAttackSyncSettings


logger = logging.getLogger("soc.mitre_sync")


def _metric_from_output(output: str, label: str) -> int:
    match = re.search(rf"{re.escape(label)}:\s*(\d+)", output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def _run_command_capture(*args, **kwargs) -> str:
    output = StringIO()
    call_command(*args, stdout=output, **kwargs)
    return output.getvalue()


def _build_summary_message(
    *,
    mitre_result: MitreAttackSyncResult,
    d3fend_load_output: str,
    d3fend_normalize_output: str,
    d3fend_mapping_output: str,
    usecase_sync_output: str,
) -> str:
    d3fend_created = (
        _metric_from_output(d3fend_load_output, "Creados")
        + _metric_from_output(d3fend_mapping_output, "D3FEND creados desde mappings")
    )
    d3fend_updated = (
        _metric_from_output(d3fend_load_output, "Actualizados")
        + _metric_from_output(d3fend_load_output, "Normalizados a código oficial")
        + _metric_from_output(d3fend_normalize_output, "Normalizados")
        + _metric_from_output(d3fend_mapping_output, "D3FEND resueltos desde mappings")
    )
    mapped_relations = _metric_from_output(d3fend_mapping_output, "Relaciones únicas procesadas")
    if not mapped_relations:
        mapped_relations = _metric_from_output(d3fend_mapping_output, "Relaciones unicas procesadas")

    usecases_checked = _metric_from_output(usecase_sync_output, "Casos revisados")
    usecases_changed = _metric_from_output(usecase_sync_output, "Casos con cambios")

    return (
        "Sincronización completa finalizada.\n"
        f"ATT&CK: existentes {MitreAttack.objects.count()}, creados {mitre_result.created}, "
        f"modificados {mitre_result.updated}, omitidos {mitre_result.skipped}.\n"
        f"D3FEND: existentes {D3Fend.objects.count()}, creados {d3fend_created}, "
        f"modificados/normalizados {d3fend_updated}.\n"
        f"Mappings D3FEND->ATT&CK: relaciones procesadas {mapped_relations}.\n"
        f"Casos: revisados {usecases_checked}, matcheados/actualizados {usecases_changed}."
    )


def run_scheduled_security_frameworks_sync(
    *,
    force: bool = False,
    settings: MitreAttackSyncSettings | None = None,
    skip_normalize: bool = False,
    skip_usecases: bool = False,
) -> MitreAttackSyncResult:
    settings = settings or MitreAttackSyncSettings.get_active()
    logger.info("framework_sync_start force=%s settings=%s", force, getattr(settings, "name", "active"))
    mitre_result = run_scheduled_mitre_attack_sync(force=force, settings=settings)

    if not mitre_result.ran:
        logger.info("framework_sync_skipped reason=%s", mitre_result.message)
        return mitre_result

    try:
        d3fend_load_output = ""
        d3fend_normalize_output = ""
        d3fend_mapping_output = ""
        usecase_sync_output = ""

        logger.info("framework_sync_stage_start stage=d3fend_load")
        d3fend_load_output = _run_command_capture("load_d3fend", "--disable-non-detect")

        if not skip_normalize:
            logger.info("framework_sync_stage_start stage=d3fend_normalize")
            d3fend_normalize_output = _run_command_capture("normalize_d3fend_codes", sleep=0)

            logger.info("framework_sync_stage_start stage=d3fend_mappings_refresh")
            d3fend_mapping_output = _run_command_capture("load_d3fend", "--mappings-only", "--disable-non-detect")

        if not skip_usecases:
            logger.info("framework_sync_stage_start stage=usecase_d3fend_sync")
            usecase_sync_output = _run_command_capture("sync_usecase_d3fends")
    except Exception as exc:
        logger.exception("framework_sync_failed stage=d3fend_or_usecases error=%s", exc)
        raise

    logger.info(
        "framework_sync_success attack_created=%s attack_updated=%s attack_skipped=%s",
        mitre_result.created,
        mitre_result.updated,
        mitre_result.skipped,
    )
    if settings:
        settings.last_message = _build_summary_message(
            mitre_result=mitre_result,
            d3fend_load_output=d3fend_load_output,
            d3fend_normalize_output=d3fend_normalize_output,
            d3fend_mapping_output=d3fend_mapping_output,
            usecase_sync_output=usecase_sync_output,
        )
        settings.save(update_fields=["last_message", "updated_at"])
    return mitre_result
