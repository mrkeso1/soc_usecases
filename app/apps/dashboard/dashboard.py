"""Dashboard aggregation helpers.

The dashboard view and the PDF export both need the same coverage metrics. Keeping
that aggregation here avoids duplicating query logic in views and report rendering.
"""

from collections import Counter
from datetime import date
import math

from django.db import models
from django.db import connection
from django.db.utils import OperationalError, ProgrammingError

from apps.mitre.coverage_overrides import get_override_map, resolve_status, split_values
from apps.mitre.models import CoverageOverride, D3Fend, MitreAttack
from apps.sources.models import EventSource, SourceType
from apps.usecases.models import UseCase
from apps.lifecycle.lifecycle import lifecycle_state
from apps.lifecycle.models import LifecycleReview
from apps.controls.models import Control
from apps.sigma_tools.models import UseCaseTechnicalBackup
from .models import MitreCoverageSnapshot


PRODUCTION_STATUS = UseCase.STATUS_PRODUCTION


SEVERITY_COLORS = {
    "Low": "#4ade80",
    "Medium": "#f5a623",
    "High": "#f97316",
    "Critical": "#ff4757",
}

STATUS_COLORS = {
    UseCase.STATUS_DEVELOPMENT: "#38bdf8",
    UseCase.STATUS_TEST: "#f5a623",
    UseCase.STATUS_PRODUCTION: "#00e5a0",
    UseCase.STATUS_RETIRED: "#94a3b8",
}

CHART_COLORS = (
    "#2d7aff",
    "#00e5a0",
    "#f5a623",
    "#a78bfa",
    "#22d3ee",
    "#ff7ab6",
    "#94a3b8",
)


def _metric_rows(values, colors=None, limit=None):
    ordered = sorted(values, key=lambda item: (-item[1], str(item[0] or "")))
    total = sum(value for _, value in ordered)
    maximum = max((value for _, value in ordered), default=0)
    if limit:
        ordered = ordered[:limit]
    rows = []
    for index, (name, value) in enumerate(ordered):
        label = name or "Sin definir"
        rows.append({
            "name": label,
            "value": value,
            "percent": round(value / total * 100) if total else 0,
            "bar_percent": round(value / maximum * 100) if maximum else 0,
            "color": (colors or {}).get(label, CHART_COLORS[index % len(CHART_COLORS)]),
        })
    return rows


def _grouped_rows(queryset, field, colors=None, limit=None):
    values = queryset.values(field).annotate(value=models.Count("id")).order_by("-value", field)
    return _metric_rows(((item[field], item["value"]) for item in values), colors, limit)


def _donut_gradient(rows):
    offset = 0
    segments = []
    for row in rows:
        end = offset + row["percent"]
        segments.append(f"{row['color']} {offset}% {end}%")
        offset = end
    if offset < 100:
        segments.append(f"rgba(148,163,184,.18) {offset}% 100%")
    return "conic-gradient(" + ", ".join(segments) + ")"


def build_executive_dashboard_context(request):
    today = date.today()
    usecases = UseCase.objects.prefetch_related("source_links__source", "mitre_attacks", "d3fends")
    operational_usecases = usecases.exclude(status__iexact=UseCase.STATUS_RETIRED)
    sources = EventSource.objects.all()
    controls = Control.objects.all()
    production_qs = operational_usecases.filter(status__iexact=PRODUCTION_STATUS, is_enabled=True)
    production_total_cases = operational_usecases.filter(status__iexact=PRODUCTION_STATUS).count()
    production_disabled_cases = operational_usecases.filter(status__iexact=PRODUCTION_STATUS, is_enabled=False).count()
    total_inventory_cases = usecases.count()
    retired_cases = usecases.filter(status__iexact=UseCase.STATUS_RETIRED).count()
    total_cases = operational_usecases.count()
    production_cases = production_qs.count()
    enabled_cases = operational_usecases.filter(is_enabled=True).count()
    priority_cases = operational_usecases.filter(severity__in=["High", "Critical"]).count()
    source_linked_cases = operational_usecases.filter(source_links__isnull=False).distinct().count()
    mitre_mapped_cases = operational_usecases.filter(mitre_attacks__isnull=False).distinct().count()
    documented_cases = operational_usecases.filter(
        models.Q(objective__gt="") | models.Q(functional_description__gt="")
    ).distinct().count()
    conditioned_cases = operational_usecases.filter(
        models.Q(full_rule_text__gt="") | models.Q(rule_conditions__isnull=False)
    ).distinct().count()
    backup_current_cases = (
        UseCaseTechnicalBackup.objects
        .filter(use_case__in=operational_usecases, is_current=True)
        .values("use_case_id")
        .distinct()
        .count()
    )
    without_sources = max(total_cases - source_linked_cases, 0)
    without_attack = max(total_cases - mitre_mapped_cases, 0)
    without_documentation = max(total_cases - documented_cases, 0)
    without_conditions = max(total_cases - conditioned_cases, 0)
    lifecycle_pending = operational_usecases.filter(
        models.Q(next_review_date__isnull=True) | models.Q(next_review_date__lt=today)
    ).count()

    active_sources = sources.filter(status=EventSource.STATUS_ACTIVE).count()
    total_sources = sources.count()
    reviewed_recently = LifecycleReview.objects.filter(checked_at__gte=today.replace(month=1, day=1)).count()
    total_controls = controls.count()
    production_controls = controls.filter(status=Control.STATUS_PRODUCTION).count()
    lifecycle = lifecycle_state(today.year, today=today)
    active_period = next(
        (item for item in lifecycle["periods"] if item["period"] == lifecycle["active_period"]),
        lifecycle["periods"][0] if lifecycle["periods"] else {},
    )
    lifecycle_period_count = len(lifecycle["periods"])
    blocked_periods = sum(1 for item in lifecycle["periods"] if item["state"] == "Bloqueado")
    lifecycle_complete = sum(1 for item in lifecycle["periods"] if item["complete"])
    lifecycle_progress = round(lifecycle_complete / lifecycle_period_count * 100) if lifecycle_period_count else 0

    severity_rows = _grouped_rows(operational_usecases, "severity", SEVERITY_COLORS)
    status_rows = _grouped_rows(usecases, "status", STATUS_COLORS)
    source_rows = _metric_rows(
        (
            (item["source_links__source__name"], item["value"])
            for item in operational_usecases.filter(source_links__isnull=False)
            .values("source_links__source__name")
            .annotate(value=models.Count("id", distinct=True))
            .order_by("-value")
        ),
        limit=8,
    )
    source_type_labels = dict(SourceType.objects.values_list("code", "name"))
    source_type_values = (
        (source_type_labels.get(item["source_type"], item["source_type"]), item["value"])
        for item in sources.values("source_type").annotate(value=models.Count("id")).order_by("-value", "source_type")
    )
    source_type_rows = _metric_rows(source_type_values, limit=8)
    source_status_rows = _grouped_rows(sources, "status", {
        EventSource.STATUS_ACTIVE: "#00e5a0",
        EventSource.STATUS_INACTIVE: "#94a3b8",
        EventSource.STATUS_PLANNED: "#f5a623",
        EventSource.STATUS_RETIRED: "#ff4757",
    })
    source_category_rows = _metric_rows(
        (
            (item["category_ref__name"], item["value"])
            for item in sources.filter(category_ref__isnull=False)
            .values("category_ref__name")
            .annotate(value=models.Count("id"))
            .order_by("-value")
        ),
        limit=8,
    )
    source_subcategory_rows = _metric_rows(
        (
            (item["subcategory_ref__name"], item["value"])
            for item in sources.filter(subcategory_ref__isnull=False)
            .values("subcategory_ref__name")
            .annotate(value=models.Count("id"))
            .order_by("-value")
        ),
        limit=8,
    )
    source_protection_rows = _grouped_rows(sources, "protection", {
        EventSource.PROTECTION_INTERNAL: "#00e5a0",
        EventSource.PROTECTION_EXTERNAL: "#2d7aff",
        EventSource.PROTECTION_MIXED: "#a78bfa",
        EventSource.PROTECTION_THIRD_PARTY: "#94a3b8",
    })
    source_protocol_rows = _metric_rows(
        (
            (item["protocol"], item["value"])
            for item in sources.exclude(protocol="")
            .values("protocol")
            .annotate(value=models.Count("id"))
            .order_by("-value", "protocol")
        ),
        limit=12,
    )
    owner_rows = _grouped_rows(operational_usecases.exclude(owner_name=""), "owner_name", limit=8)
    treatment_rows = _grouped_rows(operational_usecases.exclude(blocking_type=""), "blocking_type", limit=8)
    escalation_rows = _grouped_rows(operational_usecases.exclude(escalation=""), "escalation", limit=8)
    health_rows = _grouped_rows(operational_usecases.exclude(validation_result=""), "validation_result", {
        UseCase.VALIDATION_RESULT_OK: "#00e5a0",
        UseCase.VALIDATION_RESULT_WARNING: "#f5a623",
        UseCase.VALIDATION_RESULT_FAILED: "#ff4757",
        UseCase.VALIDATION_RESULT_NONE: "#94a3b8",
    })

    attention_total = without_sources + without_attack + without_documentation + lifecycle_pending
    inventory_quality_rows = [
        {
            "name": "Fuentes vinculadas",
            "value": source_linked_cases,
            "total": total_cases,
            "percent": _safe_percent(source_linked_cases, total_cases),
            "color": "#00e5a0",
        },
        {
            "name": "MITRE asociado",
            "value": mitre_mapped_cases,
            "total": total_cases,
            "percent": _safe_percent(mitre_mapped_cases, total_cases),
            "color": "#2d7aff",
        },
        {
            "name": "Regla / logica",
            "value": conditioned_cases,
            "total": total_cases,
            "percent": _safe_percent(conditioned_cases, total_cases),
            "color": "#a78bfa",
        },
        {
            "name": "Backup vigente",
            "value": backup_current_cases,
            "total": total_cases,
            "percent": _safe_percent(backup_current_cases, total_cases),
            "color": "#f5a623",
        },
    ]

    return {
        "today": today,
        "total_cases": total_cases,
        "total_inventory_cases": total_inventory_cases,
        "retired_cases": retired_cases,
        "production_cases": production_cases,
        "production_total_cases": production_total_cases,
        "production_disabled_cases": production_disabled_cases,
        "enabled_cases": enabled_cases,
        "priority_cases": priority_cases,
        "total_sources": total_sources,
        "active_sources": active_sources,
        "without_sources": without_sources,
        "without_attack": without_attack,
        "without_documentation": without_documentation,
        "without_conditions": without_conditions,
        "lifecycle_pending": lifecycle_pending,
        "reviewed_recently": reviewed_recently,
        "total_controls": total_controls,
        "production_controls": production_controls,
        "attention_total": attention_total,
        "active_period": active_period,
        "blocked_periods": blocked_periods,
        "lifecycle": lifecycle,
        "lifecycle_period_count": lifecycle_period_count,
        "lifecycle_complete": lifecycle_complete,
        "lifecycle_progress": lifecycle_progress,
        "documented_cases": documented_cases,
        "conditioned_cases": conditioned_cases,
        "source_linked_cases": source_linked_cases,
        "mitre_mapped_cases": mitre_mapped_cases,
        "backup_current_cases": backup_current_cases,
        "inventory_quality_rows": inventory_quality_rows,
        "production_percentage": _safe_percent(production_cases, total_cases),
        "enabled_percentage": _safe_percent(enabled_cases, total_cases),
        "priority_percentage": _safe_percent(priority_cases, total_cases),
        "documentation_percentage": _safe_percent(documented_cases, total_cases),
        "conditions_percentage": _safe_percent(conditioned_cases, total_cases),
        "source_link_percentage": _safe_percent(source_linked_cases, total_cases),
        "mitre_mapping_percentage": _safe_percent(mitre_mapped_cases, total_cases),
        "backup_percentage": _safe_percent(backup_current_cases, total_cases),
        "source_percentage": _safe_percent(active_sources, total_sources),
        "severity_rows": severity_rows,
        "status_rows": status_rows,
        "source_rows": source_rows,
        "source_type_rows": source_type_rows,
        "source_status_rows": source_status_rows,
        "source_category_rows": source_category_rows,
        "source_subcategory_rows": source_subcategory_rows,
        "source_protection_rows": source_protection_rows,
        "source_protocol_rows": source_protocol_rows,
        "owner_rows": owner_rows,
        "treatment_rows": treatment_rows,
        "escalation_rows": escalation_rows,
        "health_rows": health_rows,
        "control_status_rows": _grouped_rows(controls, "status", STATUS_COLORS),
        "control_source_rows": _metric_rows(
            (
                (item["source__name"], item["value"])
                for item in controls.filter(source__isnull=False)
                .values("source__name")
                .annotate(value=models.Count("id"))
                .order_by("-value")
            ),
            limit=8,
        ),
        "severity_gradient": _donut_gradient(severity_rows),
        "source_status_gradient": _donut_gradient(source_status_rows),
    }


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


def _format_number(value: float) -> str:
    rounded = round(value, 1)
    if rounded == int(rounded):
        return str(int(rounded))
    return str(rounded).replace(".", ",")


def _css_percent(value: float) -> str:
    percent = max(0.0, min(100.0, float(value or 0)))
    return f"{percent:.1f}"


def _svg_dashoffset(percent: float, radius: float = 80.0) -> float:
    """Return the SVG stroke offset needed for the radial progress widgets."""
    circumference = 2 * math.pi * radius
    return round(circumference * (1 - percent / 100), 2)


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


def mitre_snapshot_payload_from_context(context):
    attack_techniques_percent = context["attack_radials"][0]["percent"]
    attack_tactics_percent = context["attack_radials"][1]["percent"]
    d3fend_detect_percent = context["d3fend_radials"][0]["percent"]
    d3fend_detect_full_percent = context["d3fend_radials"][1]["percent"]
    coverage_score = round(
        (
            attack_techniques_percent
            + attack_tactics_percent
            + d3fend_detect_percent
            + d3fend_detect_full_percent
        ) / 4,
        1,
    )
    return {
        "coverage_score": coverage_score,
        "attack_techniques_covered": context["covered_attack_techniques"],
        "attack_techniques_total": context["all_attack_techniques"],
        "attack_techniques_percent": attack_techniques_percent,
        "attack_tactics_full_covered": context["covered_tactics"],
        "attack_tactics_total": context["total_tactics"],
        "attack_tactics_percent": attack_tactics_percent,
        "d3fend_detect_equivalent_covered": context["covered_d3fend_techniques"],
        "d3fend_detect_total": context["all_d3fend_techniques"],
        "d3fend_detect_percent": d3fend_detect_percent,
        "d3fend_detect_full_covered": context["fully_covered_d3fend_techniques"],
        "d3fend_detect_full_percent": d3fend_detect_full_percent,
        "payload": {
            "summary_cards": context["mitre_summary_cards"],
            "filters": {
                "enabled": context["selected_enabled"],
                "device": context["selected_device"],
                "source": context["selected_source_label"],
                "severity": context["selected_severity"],
            },
        },
    }


def save_mitre_coverage_snapshot(context, snapshot_date=None):
    snapshot_date = snapshot_date or date.today()
    values = mitre_snapshot_payload_from_context(context)
    snapshot, _ = MitreCoverageSnapshot.objects.update_or_create(
        snapshot_date=snapshot_date,
        defaults=values,
    )
    return snapshot


def build_mitre_coverage_timeline(days=90):
    today = date.today()
    qs = MitreCoverageSnapshot.objects.order_by("snapshot_date")
    if days and int(days) >= 365:
        month_index = today.month - 1 - 11
        start_year = today.year + math.floor(month_index / 12)
        start_month = (month_index % 12) + 1
        start_date = date(start_year, start_month, 1)
        qs = qs.filter(snapshot_date__gte=start_date)
    elif days:
        from datetime import timedelta
        qs = qs.filter(snapshot_date__gte=today - timedelta(days=days - 1))

    raw_rows = [
        {
            "date": snapshot.snapshot_date,
            "label": snapshot.snapshot_date.strftime("%d/%m"),
            "title": snapshot.snapshot_date.strftime("%d/%m"),
            "score": float(snapshot.coverage_score),
            "attack": float(snapshot.attack_techniques_percent),
            "tactics": float(snapshot.attack_tactics_percent),
            "d3fend": float(snapshot.d3fend_detect_percent),
            "d3fend_full": float(snapshot.d3fend_detect_full_percent),
        }
        for snapshot in qs
    ]

    month_labels = {
        1: "Ene",
        2: "Feb",
        3: "Mar",
        4: "Abr",
        5: "May",
        6: "Jun",
        7: "Jul",
        8: "Ago",
        9: "Sep",
        10: "Oct",
        11: "Nov",
        12: "Dic",
    }

    def average_rows(bucket, label, title):
        if not bucket:
            return None
        return {
            "date": bucket[-1]["date"],
            "label": label,
            "title": title,
            "score": round(sum(row["score"] for row in bucket) / len(bucket), 1),
            "attack": round(sum(row["attack"] for row in bucket) / len(bucket), 1),
            "tactics": round(sum(row["tactics"] for row in bucket) / len(bucket), 1),
            "d3fend": round(sum(row["d3fend"] for row in bucket) / len(bucket), 1),
            "d3fend_full": round(sum(row["d3fend_full"] for row in bucket) / len(bucket), 1),
        }

    rows = raw_rows
    if int(days or 0) >= 365 and raw_rows:
        monthly = {}
        for row in raw_rows:
            key = (row["date"].year, row["date"].month)
            monthly.setdefault(key, []).append(row)
        rows = []
        for (year, month), bucket in sorted(monthly.items()):
            label = month_labels[month]
            rows.append(average_rows(bucket, label, f"{label} {year}"))
        rows = rows[-12:]
    elif int(days or 0) > 30 and len(raw_rows) > 30:
        target_points = 30
        rows = []
        for index in range(target_points):
            start = math.floor(index * len(raw_rows) / target_points)
            end = math.floor((index + 1) * len(raw_rows) / target_points)
            if end <= start:
                end = start + 1
            bucket = raw_rows[start:end]
            if not bucket:
                continue
            title = (
                bucket[0]["label"]
                if bucket[0]["label"] == bucket[-1]["label"]
                else f"{bucket[0]['label']} - {bucket[-1]['label']}"
            )
            rows.append(average_rows(bucket, bucket[-1]["label"], title))

    chart_left = 8.0
    chart_right = 100.0
    chart_top = 6.0
    chart_bottom = 42.0

    def chart_y(value):
        value = max(0.0, min(100.0, float(value or 0)))
        return chart_bottom - ((value / 100.0) * (chart_bottom - chart_top))

    points = []
    chart_points = []
    latest_marker = None
    if len(rows) == 1:
        y = chart_y(rows[0]["score"])
        points = [f"{chart_left:.2f},{y:.2f}", f"{chart_right:.2f},{y:.2f}"]
        latest_marker = {"x": f"{chart_right:.2f}", "y": f"{y:.2f}", "label": rows[0]["label"]}
        chart_points.append({
            "x": f"{chart_right:.2f}",
            "y": f"{y:.2f}",
            "left": f"{(chart_right / 104.0) * 100:.2f}",
            "top": f"{(y / 50.0) * 100:.2f}",
            "label": rows[0]["label"],
            "title": rows[0]["title"],
            "score_label": _format_number(rows[0]["score"]),
        })
    elif len(rows) > 1:
        for index, row in enumerate(rows):
            x = chart_left + ((index / (len(rows) - 1)) * (chart_right - chart_left))
            y = chart_y(row["score"])
            points.append(f"{x:.2f},{y:.2f}")
            chart_points.append({
                "x": f"{x:.2f}",
                "y": f"{y:.2f}",
                "left": f"{(x / 104.0) * 100:.2f}",
                "top": f"{(y / 50.0) * 100:.2f}",
                "label": row["label"],
                "title": row["title"],
                "score_label": _format_number(row["score"]),
            })
        latest_x, latest_y = points[-1].split(",")
        latest_marker = {"x": latest_x, "y": latest_y, "label": rows[-1]["label"]}

    x_axis_labels = []
    if rows:
        if len(rows) == 1:
            label_indexes = [0]
        else:
            last_index = len(rows) - 1
            label_indexes = sorted({
                0,
                round(last_index * 0.25),
                round(last_index * 0.5),
                round(last_index * 0.75),
                last_index,
            })
        for index in label_indexes:
            if len(rows) == 1:
                x = chart_right
            else:
                x = chart_left + ((index / (len(rows) - 1)) * (chart_right - chart_left))
            x_axis_labels.append({
                "left": f"{(x / 104.0) * 100:.2f}",
                "label": rows[index]["label"],
            })
    if rows and int(days or 0) >= 365:
        range_label = f"{rows[0]['title']} - {rows[-1]['title']}"
    elif raw_rows:
        range_label = f"{raw_rows[0]['label']} - {raw_rows[-1]['label']}"
    else:
        range_label = ""

    return {
        "rows": rows[-8:],
        "points": " ".join(points),
        "chart_points": chart_points,
        "x_axis_labels": x_axis_labels,
        "latest_marker": latest_marker,
        "latest": rows[-1] if rows else None,
        "first": rows[0] if rows else None,
        "range_label": range_label,
        "count": len(rows),
        "delta": round(rows[-1]["score"] - rows[0]["score"], 1) if len(rows) > 1 else 0,
    }


def _risk_level(score):
    if score >= 80:
        return "Alto"
    if score >= 45:
        return "Medio"
    return "Bajo"


def _risk_level_class(score):
    if score >= 80:
        return "good"
    if score >= 45:
        return "medium"
    return "bad"


def build_mitre_risk_overview(context, days=90):
    timeline = build_mitre_coverage_timeline(days=days)
    score = mitre_snapshot_payload_from_context(context)["coverage_score"]
    attack_score = context["attack_radials"][0]["percent"]
    tactics_score = context["attack_radials"][1]["percent"]
    d3fend_score = context["d3fend_radials"][0]["percent"]
    d3fend_full_score = context["d3fend_radials"][1]["percent"]
    category_rows = []
    for name, row_score, color in (
        ("ATT&CK técnicas", attack_score, "#2d7aff"),
        ("ATT&CK tácticas 100%", tactics_score, "#00e5a0"),
        ("D3FEND Detect", d3fend_score, "#ff7ab6"),
        ("D3FEND 100%", d3fend_full_score, "#f5a623"),
    ):
        category_rows.append({
            "name": name,
            "score": row_score,
            "score_label": _format_number(row_score),
            "score_width": _css_percent(row_score),
            "level": _risk_level(row_score),
            "class": _risk_level_class(row_score),
            "color": color,
        })

    monthly_map = {}
    for row in timeline["rows"]:
        key = row["date"].strftime("%b")
        bucket = monthly_map.setdefault(key, {"label": key, "attack": [], "d3fend": [], "score": []})
        bucket["attack"].append(row["attack"])
        bucket["d3fend"].append(row["d3fend"])
        bucket["score"].append(row["score"])
    monthly_rows = []
    for bucket in monthly_map.values():
        attack_avg = round(sum(bucket["attack"]) / len(bucket["attack"]), 1)
        d3fend_avg = round(sum(bucket["d3fend"]) / len(bucket["d3fend"]), 1)
        score_avg = round(sum(bucket["score"]) / len(bucket["score"]), 1)
        monthly_rows.append({
            "label": bucket["label"],
            "attack": _format_number(attack_avg),
            "attack_height": _css_percent(attack_avg),
            "d3fend": _format_number(d3fend_avg),
            "d3fend_height": _css_percent(d3fend_avg),
            "score": _format_number(score_avg),
            "score_height": _css_percent(score_avg),
        })

    if not monthly_rows:
        monthly_rows = [{
            "label": date.today().strftime("%b"),
            "attack": _format_number(attack_score),
            "attack_height": _css_percent(attack_score),
            "d3fend": _format_number(d3fend_score),
            "d3fend_height": _css_percent(d3fend_score),
            "score": _format_number(score),
            "score_height": _css_percent(score),
        }]

    return {
        "score": score,
        "score_label": _format_number(score),
        "score_width": _css_percent(score),
        "level": _risk_level(score),
        "level_class": _risk_level_class(score),
        "delta": timeline["delta"],
        "points": timeline["points"],
        "chart_points": timeline["chart_points"],
        "x_axis_labels": timeline["x_axis_labels"],
        "range_label": timeline["range_label"],
        "count": timeline["count"],
        "has_history": timeline["count"] > 1,
        "categories": category_rows,
        "monthly_rows": monthly_rows[-6:],
    }


def build_dashboard_context(request):
    """Build coverage context using enabled production use cases by default.

    Draft/Test/Desarrollo/Baja cases are deliberately excluded from coverage.
    Disabled production cases are also excluded unless the user explicitly asks
    to include them through the Habilitado filter.
    """
    base_qs = (
        UseCase.objects
        .filter(status__iexact=PRODUCTION_STATUS)
        .prefetch_related("mitre_attacks", "d3fends", "source_links__source")
    )

    device = request.GET.get("device", "").strip()
    source = request.GET.get("source", "").strip()
    severity = request.GET.get("severity", "").strip()
    enabled = request.GET.get("enabled", "yes").strip() or "yes"
    if enabled not in {"yes", "no", "all"}:
        enabled = "yes"
    timeline_options = [
        {"value": "30", "label": "1 mes"},
        {"value": "90", "label": "3 meses"},
        {"value": "365", "label": "1 año"},
    ]
    selected_timeline = request.GET.get("timeline", "90").strip() or "90"
    if selected_timeline not in {item["value"] for item in timeline_options}:
        selected_timeline = "90"
    timeline_days = int(selected_timeline)

    if device:
        base_qs = base_qs.filter(device__iexact=device)
    if source.isdigit():
        base_qs = base_qs.filter(source_links__source_id=int(source))
    if severity:
        base_qs = base_qs.filter(severity__iexact=severity)
    filtered_production_qs = base_qs.distinct()
    production_total_cases = filtered_production_qs.count()
    production_enabled_cases = filtered_production_qs.filter(is_enabled=True).count()
    production_disabled_cases = filtered_production_qs.filter(is_enabled=False).count()

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
        for tactic in split_values(attack.tactic) or ["Sin táctica"]:
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

    all_tactic_names = set(tactic_attack_ids)
    any_covered_tactic_names = {
        tactic
        for tactic, attack_ids in tactic_attack_ids.items()
        if attack_ids & covered_attack_ids
    }
    fully_covered_tactic_names = {
        tactic
        for tactic, attack_ids in tactic_attack_ids.items()
        if attack_ids and attack_ids.issubset(covered_attack_ids)
    }
    uncovered_tactics = sorted(all_tactic_names - any_covered_tactic_names)
    total_tactics = len(all_tactic_names)
    covered_tactics = len(fully_covered_tactic_names)

    # D3FEND coverage is inferred from D3FEND→ATT&CK relations,
    # production-covered ATT&CK and manual/external overrides.
    d3fend_overrides = get_override_map(CoverageOverride.FRAMEWORK_D3FEND)
    d3fend_mapping_ready = _d3fend_attack_mapping_table_exists()
    d3fend_coverage_rows = []
    d3fend_detect_rows_by_id: dict[int, dict] = {}
    fully_covered_d3fend_techniques = 0
    partially_covered_d3fend_techniques = 0
    effective_d3fend_ids: set[int] = set()
    covered_from_cases: set[int] = set()

    if d3fend_mapping_ready:
        mapped_d3fends = list(
            D3Fend.objects
            .prefetch_related("related_attacks")
            .distinct()
            .order_by("code", "name")
        )
        covered_d3fend_techniques = 0.0

        for d3fend in mapped_d3fends:
            if (d3fend.category or "").casefold() != "detect":
                continue
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
            d3fend_detect_rows_by_id[d3fend.id] = {
                "id": d3fend.id,
                "code": d3fend.code,
                "name": d3fend.name,
                "covered": covered_related,
                "total": total_related,
                "percent": _safe_percent(covered_related, total_related),
                "coverage_ratio": coverage_ratio,
            }

        all_d3fend_techniques = len(effective_d3fend_ids)
        covered_d3fend_techniques = round(covered_d3fend_techniques, 1)
    else:
        covered_from_cases = set(
            D3Fend.objects
            .filter(use_cases__in=production_qs)
            .distinct()
            .values_list("id", flat=True)
        )
        effective_d3fends = []
        for d3fend in D3Fend.objects.all().order_by("code", "name"):
            if (d3fend.category or "").casefold() != "detect":
                continue
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
                is_covered = d3fend.id in covered_from_cases or status.is_fulfilled
                d3fend_detect_rows_by_id[d3fend.id] = {
                    "id": d3fend.id,
                    "code": d3fend.code,
                    "name": d3fend.name,
                    "covered": 1 if is_covered else 0,
                    "total": 1,
                    "percent": 100 if is_covered else 0,
                    "coverage_ratio": 1 if is_covered else 0,
                }
        all_d3fend_techniques = len(effective_d3fends)
        covered_d3fend_techniques = sum(
            1 for d3fend, status in effective_d3fends
            if d3fend.id in covered_from_cases or status.is_fulfilled
        )

    production_case_ids_by_tactic: dict[str, set[int]] = {}
    production_case_ids_by_d3fend: dict[int, set[int]] = {}
    attack_counter: Counter = Counter()
    d3fend_counter: Counter = Counter()

    # Single pass over production cases for dashboard counters and tactic case links.
    for usecase in production_qs:
        for attack in usecase.mitre_attacks.all():
            if attack.id not in all_attack_ids:
                continue

            technique_status = resolve_status(
                attack_overrides,
                framework=CoverageOverride.FRAMEWORK_ATTACK,
                object_type=CoverageOverride.OBJECT_TECHNIQUE,
                object_key=attack.external_id,
                default_enabled=attack.is_enabled,
            )
            if not technique_status.is_enabled:
                continue

            attack_counter[(attack.id, attack.external_id, attack.name)] += 1

            for tactic in split_values(attack.tactic) or ["Sin táctica"]:
                tactic_status = resolve_status(
                    attack_overrides,
                    framework=CoverageOverride.FRAMEWORK_ATTACK,
                    object_type=CoverageOverride.OBJECT_TACTIC,
                    object_key=tactic,
                    default_enabled=True,
                )
                if tactic_status.is_enabled:
                    production_case_ids_by_tactic.setdefault(tactic, set()).add(usecase.id)

        for d3fend in usecase.d3fends.all():
            if d3fend.id in effective_d3fend_ids:
                d3fend_counter[(d3fend.id, d3fend.code, d3fend.name)] += 1
                production_case_ids_by_d3fend.setdefault(d3fend.id, set()).add(usecase.id)

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

    d3fend_detect_coverage_rows = []
    for row in sorted(
        d3fend_detect_rows_by_id.values(),
        key=lambda item: (-item["coverage_ratio"], item["code"], item["name"]),
    )[:30]:
        production_cases = len(production_case_ids_by_d3fend.get(row["id"], set()))
        d3fend_detect_coverage_rows.append({
            "id": row["id"],
            "code": row["code"],
            "name": row["name"],
            "covered": _format_number(row["covered"]),
            "total": _format_number(row["total"]),
            "uncovered": _format_number(max(row["total"] - row["covered"], 0)),
            "percent": row["percent"],
            "percent_label": str(row["percent"]).replace(".", ","),
            "color_class": _coverage_color_class(row["percent"]),
            "production_cases": production_cases,
        })

    uncovered_attacks = [
        attack for attack in all_attacks
        if attack.id in all_attack_ids and attack.id not in covered_attack_ids
    ][:30]
    uncovered_attack_techniques = all_attack_techniques - covered_attack_techniques

    if d3fend_mapping_ready:
        uncovered_d3fends = [d3fend for coverage, d3fend in d3fend_coverage_rows if coverage < 1][:50]
    else:
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

    top_attack_techniques = [
        {"id": aid, "external_id": eid, "name": name, "count": count}
        for (aid, eid, name), count in attack_counter.most_common(10)
    ]

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
            "Tácticas ATT&CK al 100%",
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
            "D3FEND Detect al 100%",
            fully_covered_d3fend_techniques,
            all_d3fend_techniques,
            covered_label="100% cubiertos",
        ),
    ]

    mitre_summary_cards = [
        {
            "label": "Casos productivos",
            "value": total_cases,
            "detail": f"Habilitados {production_enabled_cases} / deshabilitados {production_disabled_cases}",
            "level": "neutral",
        },
        {
            "label": "ATT&CK técnicas",
            "value": f"{covered_attack_techniques}/{all_attack_techniques}",
            "detail": f"{attack_radials[0]['percent_label']}% cubierto",
            "level": attack_radials[0]["color_class"],
        },
        {
            "label": "ATT&CK tácticas",
            "value": f"{covered_tactics}/{total_tactics}",
            "detail": "Tácticas habilitadas al 100%",
            "level": attack_radials[1]["color_class"],
        },
        {
            "label": "D3FEND inferido",
            "value": f"{_format_number(covered_d3fend_techniques)}/{all_d3fend_techniques}",
            "detail": f"{d3fend_radials[0]['percent_label']}% equivalente",
            "level": d3fend_radials[0]["color_class"],
        },
        {
            "label": "D3FEND 100%",
            "value": f"{fully_covered_d3fend_techniques}/{all_d3fend_techniques}",
            "detail": "Técnicas Detect cubiertas al 100%",
            "level": d3fend_radials[1]["color_class"],
        },
    ]

    devices = (
        UseCase.objects
        .filter(status__iexact=PRODUCTION_STATUS, is_enabled=True)
        .exclude(device="")
        .values_list("device", flat=True)
        .distinct()
        .order_by("device")
    )
    sources = EventSource.objects.filter(status=EventSource.STATUS_ACTIVE).order_by("name")
    selected_source_obj = EventSource.objects.filter(pk=int(source)).first() if source.isdigit() else None

    context = {
        "production_status": PRODUCTION_STATUS,
        "coverage_scope_label": (
            "Casos de uso en Produccion y habilitados"
            if enabled == "yes"
            else "Casos de uso en Produccion deshabilitados"
            if enabled == "no"
            else "Todos los casos de uso en Produccion"
        ),
        "total_cases": total_cases,
        "production_total_cases": production_total_cases,
        "production_enabled_cases": production_enabled_cases,
        "production_disabled_cases": production_disabled_cases,
        "devices": devices,
        "sources": sources,
        "selected_device": device,
        "selected_source": source,
        "selected_source_label": selected_source_obj.display_name if selected_source_obj else "",
        "selected_severity": severity,
        "selected_enabled": enabled,
        "selected_timeline": selected_timeline,
        "timeline_options": timeline_options,
        "severity_choices": UseCase.SEVERITY_CHOICES,
        "attack_radials": attack_radials,
        "d3fend_radials": d3fend_radials,
        "mitre_summary_cards": mitre_summary_cards,
        "coverage_timeline": build_mitre_coverage_timeline(days=timeline_days),
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
        "d3fend_detect_coverage_rows": d3fend_detect_coverage_rows,
        "uncovered_attacks": uncovered_attacks,
        "uncovered_d3fends": uncovered_d3fends,
        "top_attack_techniques": top_attack_techniques,
        "top_d3fend_controls": top_d3fend_controls,
    }
    context["mitre_risk_overview"] = build_mitre_risk_overview(context, days=timeline_days)
    return context
