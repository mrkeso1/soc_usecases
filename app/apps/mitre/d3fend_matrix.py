from django.db.models import Prefetch

from .coverage_overrides import STATUS_FULFILLED, get_override_map, resolve_status
from apps.usecases.models import UseCase

from .models import CoverageOverride, D3Fend, MitreAttack


def _safe_percent(part: int | float, total: int | float) -> float:
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


def build_d3fend_matrix_context(request):
    device = request.GET.get("device", "").strip()
    severity = request.GET.get("severity", "").strip()
    sort = request.GET.get("sort", "code").strip()

    production_qs = UseCase.objects.filter(status__iexact=UseCase.STATUS_PRODUCTION, is_enabled=True)
    if device:
        production_qs = production_qs.filter(device__iexact=device)
    if severity:
        production_qs = production_qs.filter(severity__iexact=severity)
    production_qs = production_qs.distinct()

    attack_overrides = get_override_map(CoverageOverride.FRAMEWORK_ATTACK)
    d3fend_overrides = get_override_map(CoverageOverride.FRAMEWORK_D3FEND)

    raw_covered_attack_ids = set(
        MitreAttack.objects
        .filter(use_cases__in=production_qs)
        .distinct()
        .values_list("id", flat=True)
    )

    attack_status_by_id = {}
    for attack in MitreAttack.objects.all().only("id", "external_id", "is_enabled"):
        status = resolve_status(
            attack_overrides,
            framework=CoverageOverride.FRAMEWORK_ATTACK,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=attack.external_id,
            default_enabled=attack.is_enabled,
        )
        if status.is_enabled:
            attack_status_by_id[attack.id] = status

    covered_attack_ids = {
        attack_id for attack_id, status in attack_status_by_id.items()
        if attack_id in raw_covered_attack_ids or status.is_fulfilled
    }

    d3fends = (
        D3Fend.objects
        .prefetch_related(
            Prefetch(
                "related_attacks",
                queryset=MitreAttack.objects.order_by("external_id", "name"),
            )
        )
        .distinct()
        .order_by("code", "name")
    )

    rows = []
    total_relations = 0
    total_covered_relations = 0
    fully_covered = 0
    partially_covered = 0
    without_attacks = 0
    manual_fulfilled = 0

    for d3fend in d3fends:
        technique_status = resolve_status(
            d3fend_overrides,
            framework=CoverageOverride.FRAMEWORK_D3FEND,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=d3fend.code,
            default_enabled=d3fend.is_enabled,
        )
        if not technique_status.is_enabled:
            continue

        category_status = None
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

        is_manually_fulfilled = technique_status.is_fulfilled or bool(category_status and category_status.is_fulfilled)
        if is_manually_fulfilled:
            manual_fulfilled += 1

        attacks = []
        covered_count = 0
        related_attacks = [attack for attack in d3fend.related_attacks.all() if attack.id in attack_status_by_id]

        for attack in related_attacks:
            covered = attack.id in covered_attack_ids or is_manually_fulfilled
            if covered:
                covered_count += 1
            attacks.append({
                "id": attack.id,
                "external_id": attack.external_id,
                "name": attack.name,
                "covered": covered,
            })

        total_attacks = len(attacks)
        denominator = total_attacks or (1 if is_manually_fulfilled else 0)
        numerator = covered_count if total_attacks else (1 if is_manually_fulfilled else 0)
        percent = _safe_percent(numerator, denominator)

        total_relations += denominator
        total_covered_relations += numerator
        if denominator == 0:
            without_attacks += 1
        elif numerator == denominator:
            fully_covered += 1
        elif numerator > 0:
            partially_covered += 1

        override_reason = ""
        override_source = ""
        if category_status and category_status.is_fulfilled:
            override_reason = category_status.reason
            override_source = "Categoría cumplida por herramienta"
        elif technique_status.is_fulfilled:
            override_reason = technique_status.reason
            override_source = "Técnica cumplida por herramienta"

        rows.append({
            "d3fend": d3fend,
            "attacks": attacks,
            "covered_attacks": numerator,
            "total_attacks": denominator,
            "coverage_percent": percent,
            "coverage_label": str(percent).replace(".", ","),
            "coverage_width": str(percent),
            "level": _coverage_level(percent),
            "manual_fulfilled": is_manually_fulfilled,
            "override_source": override_source,
            "override_reason": override_reason,
        })

    if sort == "coverage_desc":
        rows.sort(key=lambda row: (-row["coverage_percent"], row["d3fend"].code))
    elif sort == "coverage_asc":
        rows.sort(key=lambda row: (row["coverage_percent"], row["d3fend"].code))
    elif sort == "attacks_desc":
        rows.sort(key=lambda row: (-row["total_attacks"], row["d3fend"].code))
    elif sort != "code":
        sort = "code"

    devices = (
        UseCase.objects
        .filter(status__iexact=UseCase.STATUS_PRODUCTION, is_enabled=True)
        .exclude(device="")
        .values_list("device", flat=True)
        .distinct()
        .order_by("device")
    )

    return {
        "rows": rows,
        "devices": devices,
        "severity_choices": UseCase.SEVERITY_CHOICES,
        "selected_device": device,
        "selected_severity": severity,
        "selected_sort": sort,
        "total_d3fends": len(rows),
        "total_cases": production_qs.count(),
        "total_relations": total_relations,
        "total_covered_relations": total_covered_relations,
        "overall_coverage_percent": _safe_percent(total_covered_relations, total_relations),
        "fully_covered": fully_covered,
        "partially_covered": partially_covered,
        "without_attacks": without_attacks,
        "manual_fulfilled": manual_fulfilled,
    }
