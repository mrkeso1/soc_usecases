from django.db.models import Prefetch

from .coverage_overrides import (
    STATUS_DISABLED,
    STATUS_FULFILLED,
    get_override_map,
    resolve_status,
    split_values,
)
from .models import CoverageOverride, MitreAttack, UseCase


PRODUCTION_STATUS = UseCase.STATUS_PRODUCTION


def _safe_percent(part: int, total: int) -> float:
    if not total:
        return 0.0
    return round((part / total) * 100, 1)


def _coverage_level(percent: float) -> str:
    if percent >= 80:
        return "good"
    if percent >= 40:
        return "medium"
    if percent > 0:
        return "low"
    return "empty"


def _attack_sort_key(external_id: str) -> tuple:
    """Sort ATT&CK IDs naturally: T1059 before T1059.001 and T1105."""
    raw = str(external_id or "").strip().upper().removeprefix("T")
    base, _, sub = raw.partition(".")
    base_num = int(base) if base.isdigit() else 0
    sub_num = int(sub) if sub.isdigit() else -1
    return (base_num, sub_num, external_id)


def _is_subtechnique(external_id: str) -> bool:
    return "." in str(external_id or "")


def _get_filtered_production_qs(request):
    device = request.GET.get("device", "").strip()
    severity = request.GET.get("severity", "").strip()

    qs = UseCase.objects.filter(status__iexact=PRODUCTION_STATUS, is_enabled=True)
    if device:
        qs = qs.filter(device__iexact=device)
    if severity:
        qs = qs.filter(severity__iexact=severity)

    return qs.distinct(), device, severity


def _manual_label(status, reason=""):
    if status == STATUS_FULFILLED:
        return "Cumplida por herramienta"
    if status == STATUS_DISABLED:
        return "Deshabilitada"
    return ""


def build_attack_matrix_context(request):
    """Build an ATT&CK tactic/technique coverage matrix.

    Coverage is intentionally calculated only from enabled use cases in
    Producción, plus manual/external coverage overrides. Test, Draft,
    Desarrollo, Baja or disabled cases do not count.
    """
    production_qs, selected_device, selected_severity = _get_filtered_production_qs(request)
    coverage_filter = request.GET.get("coverage", "").strip()
    sort = request.GET.get("sort", "tactic").strip()

    production_prefetch = Prefetch(
        "use_cases",
        queryset=production_qs.only("id", "name", "device", "severity"),
        to_attr="production_use_cases",
    )

    overrides = get_override_map(CoverageOverride.FRAMEWORK_ATTACK)

    # We load every ATT&CK row. The effective state is resolved through the
    # override layer, so an item disabled in the catalog can still be explicitly
    # re-enabled from the coverage administration screen if needed.
    attacks = list(
        MitreAttack.objects
        .prefetch_related(production_prefetch)
        .order_by("external_id", "name")
    )

    tactic_map: dict[str, list[dict]] = {}
    covered_attack_ids: set[int] = set()
    all_attack_ids: set[int] = set()
    all_subtechnique_ids: set[int] = set()
    covered_subtechnique_ids: set[int] = set()

    for attack in attacks:
        technique_status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_ATTACK,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=attack.external_id,
            default_enabled=attack.is_enabled,
        )
        if not technique_status.is_enabled:
            continue

        tactics = split_values(attack.tactic) or ["Sin táctica"]
        cases = sorted(
            getattr(attack, "production_use_cases", []),
            key=lambda item: (item.name or "").lower(),
        )

        for tactic in tactics:
            tactic_status = resolve_status(
                overrides,
                framework=CoverageOverride.FRAMEWORK_ATTACK,
                object_type=CoverageOverride.OBJECT_TACTIC,
                object_key=tactic,
                default_enabled=True,
            )
            if not tactic_status.is_enabled:
                continue

            manually_fulfilled = technique_status.is_fulfilled or tactic_status.is_fulfilled
            covered = bool(cases) or manually_fulfilled
            all_attack_ids.add(attack.id)
            if covered:
                covered_attack_ids.add(attack.id)
            if _is_subtechnique(attack.external_id):
                all_subtechnique_ids.add(attack.id)
                if covered:
                    covered_subtechnique_ids.add(attack.id)

            coverage_source = "case"
            coverage_note = ""
            if tactic_status.is_fulfilled:
                coverage_source = "tactic_override"
                coverage_note = tactic_status.reason
            elif technique_status.is_fulfilled:
                coverage_source = "technique_override"
                coverage_note = technique_status.reason
            elif not cases:
                coverage_source = "missing"

            technique_row = {
                "id": attack.id,
                "external_id": attack.external_id,
                "name": attack.name,
                "covered": covered,
                "manual_fulfilled": manually_fulfilled,
                "coverage_source": coverage_source,
                "coverage_note": coverage_note,
                "coverage_label": _manual_label(STATUS_FULFILLED, coverage_note) if manually_fulfilled else "",
                "production_cases_count": len(cases),
                "cases": cases[:5],
                "extra_cases_count": max(len(cases) - 5, 0),
                "is_subtechnique": _is_subtechnique(attack.external_id),
            }
            tactic_map.setdefault(tactic, []).append(technique_row)

    rows = []
    fully_covered_tactics = 0
    partially_covered_tactics = 0
    empty_tactics = 0

    for tactic, techniques in tactic_map.items():
        unique_by_id = {technique["id"]: technique for technique in techniques}
        techniques = sorted(unique_by_id.values(), key=lambda item: _attack_sort_key(item["external_id"]))

        covered_count = sum(1 for technique in techniques if technique["covered"])
        total_count = len(techniques)
        percent = _safe_percent(covered_count, total_count)
        production_case_ids = {
            case.id
            for technique in techniques
            for case in technique["cases"]
        }
        subtechnique_count = sum(1 for technique in techniques if technique["is_subtechnique"])
        covered_subtechnique_count = sum(
            1 for technique in techniques if technique["is_subtechnique"] and technique["covered"]
        )
        manual_fulfilled_count = sum(1 for technique in techniques if technique["manual_fulfilled"])

        if total_count and covered_count == total_count:
            status = "complete"
            fully_covered_tactics += 1
        elif covered_count > 0:
            status = "partial"
            partially_covered_tactics += 1
        else:
            status = "empty"
            empty_tactics += 1

        rows.append({
            "name": tactic,
            "techniques": techniques,
            "covered_techniques": covered_count,
            "total_techniques": total_count,
            "missing_techniques": total_count - covered_count,
            "coverage_percent": percent,
            "coverage_label": str(percent).replace(".", ","),
            "coverage_width": str(percent),
            "level": _coverage_level(percent),
            "status": status,
            "production_cases_count": len(production_case_ids),
            "subtechnique_count": subtechnique_count,
            "covered_subtechnique_count": covered_subtechnique_count,
            "manual_fulfilled_count": manual_fulfilled_count,
        })

    if coverage_filter == "complete":
        rows = [row for row in rows if row["status"] == "complete"]
    elif coverage_filter == "partial":
        rows = [row for row in rows if row["status"] == "partial"]
    elif coverage_filter == "empty":
        rows = [row for row in rows if row["status"] == "empty"]
    elif coverage_filter:
        coverage_filter = ""

    if sort == "coverage_desc":
        rows.sort(key=lambda row: (-row["coverage_percent"], row["name"].lower()))
    elif sort == "coverage_asc":
        rows.sort(key=lambda row: (row["coverage_percent"], row["name"].lower()))
    elif sort == "missing_desc":
        rows.sort(key=lambda row: (-row["missing_techniques"], row["name"].lower()))
    elif sort == "techniques_desc":
        rows.sort(key=lambda row: (-row["total_techniques"], row["name"].lower()))
    else:
        sort = "tactic"
        rows.sort(key=lambda row: row["name"].lower())

    devices = (
        UseCase.objects
        .filter(status__iexact=PRODUCTION_STATUS)
        .exclude(device="")
        .values_list("device", flat=True)
        .distinct()
        .order_by("device")
    )

    covered_techniques = len(covered_attack_ids)
    total_techniques = len(all_attack_ids)
    total_subtechniques = len(all_subtechnique_ids)
    covered_subtechniques = len(covered_subtechnique_ids)
    manual_covered_techniques = sum(
        1
        for row in rows
        for technique in row["techniques"]
        if technique["manual_fulfilled"]
    )

    return {
        "rows": rows,
        "devices": devices,
        "severity_choices": UseCase.SEVERITY_CHOICES,
        "selected_device": selected_device,
        "selected_severity": selected_severity,
        "selected_coverage": coverage_filter,
        "selected_sort": sort,
        "total_cases": production_qs.count(),
        "total_tactics": len(tactic_map),
        "visible_tactics": len(rows),
        "fully_covered_tactics": fully_covered_tactics,
        "partially_covered_tactics": partially_covered_tactics,
        "empty_tactics": empty_tactics,
        "covered_techniques": covered_techniques,
        "total_techniques": total_techniques,
        "missing_techniques": total_techniques - covered_techniques,
        "overall_coverage_percent": _safe_percent(covered_techniques, total_techniques),
        "covered_subtechniques": covered_subtechniques,
        "total_subtechniques": total_subtechniques,
        "subtechnique_coverage_percent": _safe_percent(covered_subtechniques, total_subtechniques),
        "manual_covered_techniques": manual_covered_techniques,
    }
