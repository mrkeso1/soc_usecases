"""Dashboard aggregation helpers.

The dashboard view and the PDF export both need the same coverage metrics. Keeping
that aggregation here avoids duplicating query logic in views and report rendering.
"""

from collections import Counter
import math

from django.db import connection
from django.db.utils import OperationalError, ProgrammingError

from .coverage_overrides import get_override_map, resolve_status, split_values
from .models import CoverageOverride, D3Fend, MitreAttack, UseCase


PRODUCTION_STATUS = "Producción"


def _coverage_color_class(percent: float) -> str:
    if percent >= 80:
        return "good"
    if percent >= 40:
        return "medium"
    return "bad"


def _safe_percent(part: float, total: float) -> float:
    if not total:
        return 0.0
    return round((part / total) * 100, 1)


def _svg_dashoffset(percent: float, radius: float = 80.0) -> float:
    """Return the SVG stroke offset needed for the radial progress widgets."""
    circumference = 2 * math.pi * radius
    return round(circumference * (1 - percent / 100), 2)


def _split_tactics(raw_value: str) -> list[str]:
    return split_values(raw_value)


def _d3fend_attack_mapping_table_exists() -> bool:
    """Return whether the D3FEND→ATT&CK M2M table has been migrated."""
    table_name = D3Fend.related_attacks.through._meta.db_table
    try:
        return table_name in connection.introspection.table_names()
    except (OperationalError, ProgrammingError):
        return False


def _build_radial_metric(
    title: str,
    covered: float,
    total: float,
    covered_label: str = "Cubiertas",
) -> dict:
    percent = _safe_percent(covered, total)
    covered_value = round(covered, 1) if isinstance(covered, float) else covered
    return {
        "title": title,
        "covered": covered_value,
        "total": total,
        "percent": percent,
        "percent_label": str(percent).replace(".", ","),
        "color_class": _coverage_color_class(percent),
        "covered_label": covered_label,
        "dashoffset": _svg_dashoffset(percent),
    }


def build_dashboard_context(request):
    """Build coverage context using production use cases only.

    Draft/Test/Desarrollo/Baja cases are deliberately excluded from all coverage
    metrics so they cannot inflate ATT&CK/D3FEND coverage. The dashboard links
    point back to the inventory, whose front-end filters are also production-only.
    """
    base_qs = (
        UseCase.objects
        .filter(status__iexact=PRODUCTION_STATUS)
        .prefetch_related("mitre_attacks", "d3fends")
    )

    device = request.GET.get("device", "").strip()
    severity = request.GET.get("severity", "").strip()
    enabled = request.GET.get("enabled", "").strip()

    if device:
        base_qs = base_qs.filter(device__iexact=device)
    if severity:
        base_qs = base_qs.filter(severity__iexact=severity)
    if enabled == "yes":
        base_qs = base_qs.filter(is_enabled=True)
    elif enabled == "no":
        base_qs = base_qs.filter(is_enabled=False)

    production_qs = base_qs.distinct()
    total_cases = production_qs.count()

    # ATT&CK coverage uses enabled techniques as denominator and production
    # use-case mappings plus manual/external overrides as numerator.
    attack_overrides = get_override_map(CoverageOverride.FRAMEWORK_ATTACK)
    raw_covered_attack_ids = set(
        MitreAttack.objects
        .filter(use_cases__in=production_qs)
        .distinct()
        .values_list("id", flat=True)
    )
    all_attacks = list(MitreAttack.objects.all().order_by("external_id", "name"))

    all_attack_ids: set[int] = set()
    covered_attack_ids: set[int] = set()
    tactic_attack_ids: dict[str, set[int]] = {}
    tactic_covered_attack_ids: dict[str, set[int]] = {}

    for attack in all_attacks:
        technique_status = resolve_status(
            attack_overrides,
            framework=CoverageOverride.FRAMEWORK_ATTACK,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=attack.external_id,
            default_enabled=attack.is_enabled,
        )
        if not technique_status.is_enabled:
            continue
        for tactic in _split_tactics(attack.tactic) or ["Sin táctica"]:
            tactic_status = resolve_status(
                attack_overrides,
                framework=CoverageOverride.FRAMEWORK_ATTACK,
                object_type=CoverageOverride.OBJECT_TACTIC,
                object_key=tactic,
                default_enabled=True,
            )
            if not tactic_status.is_enabled:
                continue
            tactic_attack_ids.setdefault(tactic, set()).add(attack.id)
            all_attack_ids.add(attack.id)
            if attack.id in raw_covered_attack_ids or technique_status.is_fulfilled or tactic_status.is_fulfilled:
                covered_attack_ids.add(attack.id)
                tactic_covered_attack_ids.setdefault(tactic, set()).add(attack.id)

    all_attack_techniques = len(all_attack_ids)
    covered_attack_techniques = len(covered_attack_ids)

    production_case_ids_by_tactic: dict[str, set[int]] = {}
    for usecase in production_qs:
        for attack in usecase.mitre_attacks.all():
            technique_status = resolve_status(
                attack_overrides,
                framework=CoverageOverride.FRAMEWORK_ATTACK,
                object_type=CoverageOverride.OBJECT_TECHNIQUE,
                object_key=attack.external_id,
                default_enabled=attack.is_enabled,
            )
            if not technique_status.is_enabled:
                continue
            for tactic in _split_tactics(attack.tactic) or ["Sin táctica"]:
                tactic_status = resolve_status(
                    attack_overrides,
                    framework=CoverageOverride.FRAMEWORK_ATTACK,
                    object_type=CoverageOverride.OBJECT_TACTIC,
                    object_key=tactic,
                    default_enabled=True,
                )
                if tactic_status.is_enabled:
                    production_case_ids_by_tactic.setdefault(tactic, set()).add(usecase.id)

    all_tactic_names = set(tactic_attack_ids)
    covered_tactic_names = {
        tactic
        for tactic, attack_ids in tactic_attack_ids.items()
        if attack_ids & covered_attack_ids
    }
    uncovered_tactics = sorted(all_tactic_names - covered_tactic_names)

    tactic_coverage_rows = []
    for tactic in sorted(all_tactic_names):
        attack_ids = tactic_attack_ids[tactic]
        tactic_covered_ids = tactic_covered_attack_ids.get(tactic, set())
        covered_count = len(attack_ids & covered_attack_ids) if tactic not in tactic_covered_attack_ids else len(tactic_covered_ids)
        total_count = len(attack_ids)
        percent = _safe_percent(covered_count, total_count)
        production_cases = len(production_case_ids_by_tactic.get(tactic, set()))
        tactic_coverage_rows.append({
            "name": tactic,
            "covered": covered_count,
            "total": total_count,
            "uncovered": total_count - covered_count,
            "percent": percent,
            "percent_label": str(percent).replace(".", ","),
            "color_class": _coverage_color_class(percent),
            "production_cases": production_cases,
        })

    total_tactics = len(all_tactic_names)
    covered_tactics = len(covered_tactic_names)

    # D3FEND coverage is inferred from D3FEND→ATT&CK relations,
    # production-covered ATT&CK and manual/external overrides.
    d3fend_overrides = get_override_map(CoverageOverride.FRAMEWORK_D3FEND)
    d3fend_mapping_ready = _d3fend_attack_mapping_table_exists()
    d3fend_coverage_rows = []
    fully_covered_d3fend_techniques = 0
    partially_covered_d3fend_techniques = 0

    effective_d3fend_ids: set[int] = set()
    if d3fend_mapping_ready:
        mapped_d3fends = list(
            D3Fend.objects
            .prefetch_related("related_attacks")
            .distinct()
            .order_by("code", "name")
        )
        covered_d3fend_techniques = 0.0

        for d3fend in mapped_d3fends:
            technique_status = resolve_status(
                d3fend_overrides,
                framework=CoverageOverride.FRAMEWORK_D3FEND,
                object_type=CoverageOverride.OBJECT_TECHNIQUE,
                object_key=d3fend.code,
                default_enabled=d3fend.is_enabled,
            )
            if not technique_status.is_enabled:
                continue
            if d3fend.category:
                category_status = resolve_status(
                    d3fend_overrides,
                    framework=CoverageOverride.FRAMEWORK_D3FEND,
                    object_type=CoverageOverride.OBJECT_CATEGORY,
                    object_key=d3fend.category,
                    default_enabled=True,
                )
                if not category_status.is_enabled:
                    continue
            else:
                category_status = None

            effective_d3fend_ids.add(d3fend.id)
            manually_fulfilled = technique_status.is_fulfilled or bool(category_status and category_status.is_fulfilled)
            related_attack_ids = {attack.id for attack in d3fend.related_attacks.all() if attack.id in all_attack_ids}
            total_related = len(related_attack_ids) or (1 if manually_fulfilled else 0)
            covered_related = len(related_attack_ids & covered_attack_ids)
            if manually_fulfilled:
                covered_related = total_related
            coverage_ratio = (covered_related / total_related) if total_related else 0.0
            covered_d3fend_techniques += coverage_ratio
            if coverage_ratio >= 1:
                fully_covered_d3fend_techniques += 1
            elif coverage_ratio > 0:
                partially_covered_d3fend_techniques += 1
            d3fend.coverage_percent = round(coverage_ratio * 100, 1)
            d3fend.covered_related_attacks = covered_related
            d3fend.total_related_attacks = total_related
            d3fend.manual_fulfilled = manually_fulfilled
            d3fend_coverage_rows.append((coverage_ratio, d3fend))

        all_d3fend_techniques = len(effective_d3fend_ids)
        covered_d3fend_techniques = round(covered_d3fend_techniques, 1)
    else:
        effective_d3fends = []
        for d3fend in D3Fend.objects.all().order_by("code", "name"):
            status = resolve_status(
                d3fend_overrides,
                framework=CoverageOverride.FRAMEWORK_D3FEND,
                object_type=CoverageOverride.OBJECT_TECHNIQUE,
                object_key=d3fend.code,
                default_enabled=d3fend.is_enabled,
            )
            if status.is_enabled:
                effective_d3fends.append((d3fend, status))
                effective_d3fend_ids.add(d3fend.id)
        all_d3fend_techniques = len(effective_d3fends)
        covered_from_cases = set(
            D3Fend.objects.filter(use_cases__in=production_qs).distinct().values_list("id", flat=True)
        )
        covered_d3fend_techniques = sum(
            1 for d3fend, status in effective_d3fends
            if d3fend.id in covered_from_cases or status.is_fulfilled
        )

    uncovered_attacks = [
        attack for attack in all_attacks
        if attack.id in all_attack_ids and attack.id not in covered_attack_ids
    ][:30]
    uncovered_attack_techniques = all_attack_techniques - covered_attack_techniques

    if d3fend_mapping_ready:
        uncovered_d3fends = [d3fend for coverage, d3fend in d3fend_coverage_rows if coverage < 1][:50]
    else:
        covered_from_cases = set(
            D3Fend.objects.filter(use_cases__in=production_qs).distinct().values_list("id", flat=True)
        )
        uncovered_d3fends = []
        for d3fend in D3Fend.objects.all().order_by("code", "name"):
            status = resolve_status(
                d3fend_overrides,
                framework=CoverageOverride.FRAMEWORK_D3FEND,
                object_type=CoverageOverride.OBJECT_TECHNIQUE,
                object_key=d3fend.code,
                default_enabled=d3fend.is_enabled,
            )
            if status.is_enabled and not status.is_fulfilled and d3fend.id not in covered_from_cases:
                uncovered_d3fends.append(d3fend)
            if len(uncovered_d3fends) >= 30:
                break

    attack_counter: Counter = Counter()
    for uc in production_qs:
        for attack in uc.mitre_attacks.all():
            if attack.id in all_attack_ids:
                attack_counter[(attack.id, attack.external_id, attack.name)] += 1

    top_attack_techniques = [
        {"id": aid, "external_id": eid, "name": name, "count": count}
        for (aid, eid, name), count in attack_counter.most_common(10)
    ]

    d3fend_counter: Counter = Counter()
    for uc in production_qs:
        for d3 in uc.d3fends.all():
            if d3.id in effective_d3fend_ids:
                d3fend_counter[(d3.id, d3.code, d3.name)] += 1

    top_d3fend_controls = [
        {"id": did, "code": code, "name": name, "count": count}
        for (did, code, name), count in d3fend_counter.most_common(10)
    ]

    attack_radials = [
        _build_radial_metric(
            "Cobertura Técnicas ATT&CK",
            covered_attack_techniques,
            all_attack_techniques,
        ),
        _build_radial_metric(
            "Cobertura Tácticas ATT&CK",
            covered_tactics,
            total_tactics,
        ),
    ]

    d3fend_global_metric = _build_radial_metric(
        "Cobertura D3FEND inferida por ATT&CK",
        covered_d3fend_techniques,
        all_d3fend_techniques,
        covered_label="Equivalente cubierto",
    )

    d3fend_radials = [
        d3fend_global_metric,
        _build_radial_metric(
            "D3FEND totalmente cubiertos",
            fully_covered_d3fend_techniques,
            all_d3fend_techniques,
            covered_label="100% cubiertos",
        ),
    ]

    devices = (
        UseCase.objects
        .filter(status__iexact=PRODUCTION_STATUS)
        .exclude(device="")
        .values_list("device", flat=True)
        .distinct()
        .order_by("device")
    )

    return {
        "production_status": PRODUCTION_STATUS,
        "coverage_scope_label": "Solo casos de uso en Producción",
        "total_cases": total_cases,
        "devices": devices,
        "selected_device": device,
        "selected_severity": severity,
        "selected_enabled": enabled,
        "severity_choices": UseCase.SEVERITY_CHOICES,
        "attack_radials": attack_radials,
        "d3fend_radials": d3fend_radials,
        "covered_attack_techniques": covered_attack_techniques,
        "all_attack_techniques": all_attack_techniques,
        "uncovered_attack_techniques": uncovered_attack_techniques,
        "covered_tactics": covered_tactics,
        "total_tactics": total_tactics,
        "uncovered_tactics": uncovered_tactics,
        "tactic_coverage_rows": tactic_coverage_rows,
        "covered_d3fend_techniques": covered_d3fend_techniques,
        "all_d3fend_techniques": all_d3fend_techniques,
        "fully_covered_d3fend_techniques": fully_covered_d3fend_techniques,
        "partially_covered_d3fend_techniques": partially_covered_d3fend_techniques,
        "global_d3fend_coverage_percent": d3fend_global_metric["percent"],
        "d3fend_coverage_rows": d3fend_coverage_rows,
        "uncovered_attacks": uncovered_attacks,
        "uncovered_d3fends": uncovered_d3fends,
        "top_attack_techniques": top_attack_techniques,
        "top_d3fend_controls": top_d3fend_controls,
    }
