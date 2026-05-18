from django.db.models import Prefetch

from .models import D3Fend, MitreAttack, UseCase


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


def build_d3fend_matrix_context(request):
    device = request.GET.get("device", "").strip()
    severity = request.GET.get("severity", "").strip()
    enabled = request.GET.get("enabled", "").strip()
    sort = request.GET.get("sort", "code").strip()

    production_qs = UseCase.objects.filter(status__iexact="Producción")
    if device:
        production_qs = production_qs.filter(device__iexact=device)
    if severity:
        production_qs = production_qs.filter(severity__iexact=severity)
    if enabled == "yes":
        production_qs = production_qs.filter(is_enabled=True)
    elif enabled == "no":
        production_qs = production_qs.filter(is_enabled=False)
    production_qs = production_qs.distinct()

    covered_attack_ids = set(
        MitreAttack.objects
        .filter(use_cases__in=production_qs)
        .distinct()
        .values_list("id", flat=True)
    )

    d3fends = (
        D3Fend.objects
        .prefetch_related(
            Prefetch(
                "related_attacks",
                queryset=MitreAttack.objects.order_by("external_id", "name"),
            )
        )
        .order_by("code", "name")
    )

    rows = []
    total_relations = 0
    total_covered_relations = 0
    fully_covered = 0
    partially_covered = 0
    without_attacks = 0

    for d3fend in d3fends:
        attacks = []
        covered_count = 0
        related_attacks = list(d3fend.related_attacks.all())
        for attack in related_attacks:
            covered = attack.id in covered_attack_ids
            if covered:
                covered_count += 1
            attacks.append({
                "id": attack.id,
                "external_id": attack.external_id,
                "name": attack.name,
                "covered": covered,
            })

        total_attacks = len(attacks)
        percent = _safe_percent(covered_count, total_attacks)
        total_relations += total_attacks
        total_covered_relations += covered_count
        if total_attacks == 0:
            without_attacks += 1
        elif covered_count == total_attacks:
            fully_covered += 1
        elif covered_count > 0:
            partially_covered += 1

        rows.append({
            "d3fend": d3fend,
            "attacks": attacks,
            "covered_attacks": covered_count,
            "total_attacks": total_attacks,
            "coverage_percent": percent,
            "coverage_label": str(percent).replace(".", ","),
            "coverage_width": str(percent),
            "level": _coverage_level(percent),
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
        "selected_enabled": enabled,
        "selected_sort": sort,
        "total_d3fends": len(rows),
        "total_cases": production_qs.count(),
        "total_relations": total_relations,
        "total_covered_relations": total_covered_relations,
        "overall_coverage_percent": _safe_percent(total_covered_relations, total_relations),
        "fully_covered": fully_covered,
        "partially_covered": partially_covered,
        "without_attacks": without_attacks,
    }
