"""Dashboard aggregation helpers.

The dashboard view and the PDF export both need the same coverage metrics. Keeping
that aggregation here avoids duplicating query logic in views and report rendering.
"""

from collections import Counter
import math

from .models import D3Fend, MitreAttack, UseCase


def _coverage_color_class(percent: float) -> str:
    if percent >= 80:
        return "good"
    if percent >= 40:
        return "medium"
    return "bad"


def _safe_percent(part: int, total: int) -> float:
    if not total:
        return 0.0
    return round((part / total) * 100, 1)


def _svg_dashoffset(percent: float, radius: float = 80.0) -> float:
    """Return the SVG stroke offset needed for the radial progress widgets."""
    circumference = 2 * math.pi * radius
    return round(circumference * (1 - percent / 100), 2)


def _build_radial_metric(
    title: str,
    covered: int,
    total: int,
    covered_label: str = "Cubiertas",
) -> dict:
    percent = _safe_percent(covered, total)
    return {
        "title": title,
        "covered": covered,
        "total": total,
        "percent": percent,
        "percent_label": str(percent).replace(".", ","),
        "color_class": _coverage_color_class(percent),
        "covered_label": covered_label,
        "dashoffset": _svg_dashoffset(percent),
    }


def build_dashboard_context(request):
    """Build the production coverage context shared by the dashboard UI and PDF."""
    base_qs = (
        UseCase.objects
        .filter(status__iexact="Producción")
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

    # ATT&CK coverage uses enabled techniques as the denominator and
    # production use-case mappings as the numerator.
    all_attack_techniques = MitreAttack.objects.filter(is_enabled=True).count()
    covered_attack_techniques = (
        MitreAttack.objects.filter(is_enabled=True, use_cases__in=production_qs).distinct().count()
    )

    covered_tactic_names: set[str] = set()
    for attack in MitreAttack.objects.filter(is_enabled=True, use_cases__in=production_qs).distinct():
        if attack.tactic:
            covered_tactic_names.update(
                t.strip() for t in str(attack.tactic).split(",") if t.strip()
            )

    all_tactic_names: set[str] = set()
    for attack in MitreAttack.objects.filter(is_enabled=True).exclude(tactic=""):
        all_tactic_names.update(
            t.strip() for t in str(attack.tactic).split(",") if t.strip()
        )

    total_tactics = len(all_tactic_names)
    covered_tactics = len(covered_tactic_names)
    uncovered_tactics = sorted(all_tactic_names - covered_tactic_names)

    # D3FEND coverage mirrors ATT&CK coverage and also counts use cases that
    # have at least one D3FEND control mapped.
    all_d3fend_techniques = D3Fend.objects.filter(is_enabled=True).count()
    covered_d3fend_techniques = (
        D3Fend.objects.filter(is_enabled=True, use_cases__in=production_qs).distinct().count()
    )
    productive_with_d3fend = (
        production_qs.filter(d3fends__isnull=False).distinct().count()
    )

    uncovered_attacks = (
        MitreAttack.objects
        .filter(is_enabled=True)
        .exclude(use_cases__in=production_qs)
        .distinct()
        .order_by("external_id", "name")[:20]
    )

    uncovered_d3fends = (
        D3Fend.objects
        .filter(is_enabled=True)
        .exclude(use_cases__in=production_qs)
        .distinct()
        .order_by("code", "name")[:20]
    )

    attack_counter: Counter = Counter()
    for uc in production_qs:
        for attack in uc.mitre_attacks.all():
            attack_counter[(attack.id, attack.external_id, attack.name)] += 1

    top_attack_techniques = [
        {"id": aid, "external_id": eid, "name": name, "count": count}
        for (aid, eid, name), count in attack_counter.most_common(10)
    ]

    d3fend_counter: Counter = Counter()
    for uc in production_qs:
        for d3 in uc.d3fends.all():
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

    d3fend_radials = [
        _build_radial_metric(
            "Cobertura Técnicas D3FEND",
            covered_d3fend_techniques,
            all_d3fend_techniques,
        ),
        _build_radial_metric(
            "Casos productivos con D3FEND",
            productive_with_d3fend,
            total_cases,
            covered_label="Con D3FEND",
        ),
    ]

    devices = (
        UseCase.objects
        .exclude(device="")
        .values_list("device", flat=True)
        .distinct()
        .order_by("device")
    )

    return {
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
        "covered_tactics": covered_tactics,
        "total_tactics": total_tactics,
        "uncovered_tactics": uncovered_tactics,
        "covered_d3fend_techniques": covered_d3fend_techniques,
        "all_d3fend_techniques": all_d3fend_techniques,
        "productive_with_d3fend": productive_with_d3fend,
        "uncovered_attacks": uncovered_attacks,
        "uncovered_d3fends": uncovered_d3fends,
        "top_attack_techniques": top_attack_techniques,
        "top_d3fend_controls": top_d3fend_controls,
    }
