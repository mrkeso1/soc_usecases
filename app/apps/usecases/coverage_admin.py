"""Context builders for the manual coverage administration screen."""

from collections import Counter

from django.core.paginator import Paginator

from .coverage_overrides import get_override_map, item_matches_query, resolve_status, split_values
from .models import CoverageOverride, D3Fend, MitreAttack


def _status_options():
    return CoverageOverride.STATUS_CHOICES


def _build_attack_tactic_rows(q: str, overrides: dict) -> list[dict]:
    tactic_map: dict[str, dict] = {}
    qs = MitreAttack.objects.all().only("external_id", "name", "tactic", "is_enabled").order_by("external_id", "name")
    for attack in qs:
        attack_tactics = split_values(attack.tactic) or ["Sin tactica"]
        for tactic in attack_tactics:
            data = tactic_map.setdefault(
                tactic,
                {
                    "techniques": 0,
                    "enabled": 0,
                    "fulfilled": 0,
                    "disabled": 0,
                    "search_values": {tactic},
                },
            )
            data["search_values"].update([attack.external_id, attack.name, attack.tactic])
            technique_status = resolve_status(
                overrides,
                framework=CoverageOverride.FRAMEWORK_ATTACK,
                object_type=CoverageOverride.OBJECT_TECHNIQUE,
                object_key=attack.external_id,
                default_enabled=attack.is_enabled,
            )
            data["techniques"] += 1
            if technique_status.status == CoverageOverride.STATUS_FULFILLED:
                data["fulfilled"] += 1
            elif technique_status.status == CoverageOverride.STATUS_DISABLED:
                data["disabled"] += 1
            else:
                data["enabled"] += 1

    rows = []
    for tactic, data in tactic_map.items():
        # The tactic tab should also match child technique IDs/names.
        if not item_matches_query(data["search_values"], q):
            continue
        status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_ATTACK,
            object_type=CoverageOverride.OBJECT_TACTIC,
            object_key=tactic,
            default_enabled=True,
        )
        rows.append({
            "framework": CoverageOverride.FRAMEWORK_ATTACK,
            "object_type": CoverageOverride.OBJECT_TACTIC,
            "object_type_label": "Tactica",
            "object_key": tactic,
            "object_name": tactic,
            "title": tactic,
            "subtitle": f"{data['techniques']} tecnicas/subtecnicas - {data['fulfilled']} cumplidas - {data['disabled']} deshabilitadas",
            "status": status.status,
            "status_label": status.label,
            "status_class": status.css_class,
            "reason": status.reason,
            "default_enabled": True,
            "source": status.source,
        })
    return sorted(rows, key=lambda row: row["title"].lower())


def _build_attack_technique_rows(q: str, overrides: dict) -> list[dict]:
    rows = []
    qs = MitreAttack.objects.all().order_by("external_id", "name")
    for attack in qs:
        if not item_matches_query([attack.external_id, attack.name, attack.tactic], q):
            continue
        status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_ATTACK,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=attack.external_id,
            default_enabled=attack.is_enabled,
        )
        rows.append({
            "framework": CoverageOverride.FRAMEWORK_ATTACK,
            "object_type": CoverageOverride.OBJECT_TECHNIQUE,
            "object_type_label": "Tecnica",
            "object_key": attack.external_id,
            "object_name": attack.name,
            "title": f"{attack.external_id} - {attack.name or 'Sin nombre'}",
            "subtitle": attack.tactic or "Sin tactica",
            "status": status.status,
            "status_label": status.label,
            "status_class": status.css_class,
            "reason": status.reason,
            "default_enabled": attack.is_enabled,
            "source": status.source,
        })
    return rows


def _build_d3fend_category_rows(q: str, overrides: dict) -> list[dict]:
    category_map: dict[str, dict] = {}
    qs = D3Fend.objects.all().only("code", "name", "category", "is_enabled").order_by("category", "code")
    for d3fend in qs:
        category = d3fend.category or "Sin categoria"
        data = category_map.setdefault(
            category,
            {
                "techniques": 0,
                "enabled": 0,
                "fulfilled": 0,
                "disabled": 0,
                "search_values": {category},
            },
        )
        data["search_values"].update([d3fend.code, d3fend.name, d3fend.category])
        technique_status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_D3FEND,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=d3fend.code,
            default_enabled=d3fend.is_enabled,
        )
        data["techniques"] += 1
        if technique_status.status == CoverageOverride.STATUS_FULFILLED:
            data["fulfilled"] += 1
        elif technique_status.status == CoverageOverride.STATUS_DISABLED:
            data["disabled"] += 1
        else:
            data["enabled"] += 1

    rows = []
    for category, data in category_map.items():
        # The category tab should also match child D3FEND codes/names.
        if not item_matches_query(data["search_values"], q):
            continue
        status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_D3FEND,
            object_type=CoverageOverride.OBJECT_CATEGORY,
            object_key=category,
            default_enabled=True,
        )
        rows.append({
            "framework": CoverageOverride.FRAMEWORK_D3FEND,
            "object_type": CoverageOverride.OBJECT_CATEGORY,
            "object_type_label": "Categoria",
            "object_key": category,
            "object_name": category,
            "title": category,
            "subtitle": f"{data['techniques']} tecnicas - {data['fulfilled']} cumplidas - {data['disabled']} deshabilitadas",
            "status": status.status,
            "status_label": status.label,
            "status_class": status.css_class,
            "reason": status.reason,
            "default_enabled": True,
            "source": status.source,
        })
    return sorted(rows, key=lambda row: row["title"].lower())


def _build_d3fend_technique_rows(q: str, overrides: dict) -> list[dict]:
    rows = []
    qs = D3Fend.objects.all().order_by("code", "name")
    for d3fend in qs:
        if not item_matches_query([d3fend.code, d3fend.name, d3fend.category], q):
            continue
        status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_D3FEND,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=d3fend.code,
            default_enabled=d3fend.is_enabled,
        )
        rows.append({
            "framework": CoverageOverride.FRAMEWORK_D3FEND,
            "object_type": CoverageOverride.OBJECT_TECHNIQUE,
            "object_type_label": "Tecnica",
            "object_key": d3fend.code,
            "object_name": d3fend.name,
            "title": f"{d3fend.code} - {d3fend.name or 'Sin nombre'}",
            "subtitle": d3fend.category or "Sin categoria",
            "status": status.status,
            "status_label": status.label,
            "status_class": status.css_class,
            "reason": status.reason,
            "default_enabled": d3fend.is_enabled,
            "source": status.source,
        })
    return rows


def build_coverage_admin_context(query_params) -> dict:
    tab = query_params.get("tab", CoverageOverride.FRAMEWORK_ATTACK).strip().upper()
    if tab not in {CoverageOverride.FRAMEWORK_ATTACK, CoverageOverride.FRAMEWORK_D3FEND}:
        tab = CoverageOverride.FRAMEWORK_ATTACK

    if tab == CoverageOverride.FRAMEWORK_ATTACK:
        scope = query_params.get("scope", CoverageOverride.OBJECT_TACTIC).strip().lower()
        allowed_scopes = {CoverageOverride.OBJECT_TACTIC, CoverageOverride.OBJECT_TECHNIQUE}
    else:
        scope = query_params.get("scope", CoverageOverride.OBJECT_CATEGORY).strip().lower()
        allowed_scopes = {CoverageOverride.OBJECT_CATEGORY, CoverageOverride.OBJECT_TECHNIQUE}
    if scope not in allowed_scopes:
        scope = CoverageOverride.OBJECT_TACTIC if tab == CoverageOverride.FRAMEWORK_ATTACK else CoverageOverride.OBJECT_CATEGORY

    q = query_params.get("q", "").strip()
    status_filter = query_params.get("status", "").strip()
    if status_filter not in {"", CoverageOverride.STATUS_ENABLED, CoverageOverride.STATUS_FULFILLED, CoverageOverride.STATUS_DISABLED}:
        status_filter = ""

    overrides = get_override_map(tab)
    if tab == CoverageOverride.FRAMEWORK_ATTACK and scope == CoverageOverride.OBJECT_TACTIC:
        rows = _build_attack_tactic_rows(q, overrides)
    elif tab == CoverageOverride.FRAMEWORK_ATTACK:
        rows = _build_attack_technique_rows(q, overrides)
    elif scope == CoverageOverride.OBJECT_CATEGORY:
        rows = _build_d3fend_category_rows(q, overrides)
    else:
        rows = _build_d3fend_technique_rows(q, overrides)

    counters = Counter(row["status"] for row in rows)
    if status_filter:
        rows = [row for row in rows if row["status"] == status_filter]

    paginator = Paginator(rows, 25)
    page_obj = paginator.get_page(query_params.get("page"))

    return {
        "rows": page_obj.object_list,
        "page_obj": page_obj,
        "paginator": paginator,
        "tab": tab,
        "scope": scope,
        "q": q,
        "status_filter": status_filter,
        "status_options": _status_options(),
        "counters": counters,
        "counter_enabled": counters.get(CoverageOverride.STATUS_ENABLED, 0),
        "counter_fulfilled": counters.get(CoverageOverride.STATUS_FULFILLED, 0),
        "counter_disabled": counters.get(CoverageOverride.STATUS_DISABLED, 0),
        "total_rows": len(rows),
        "attack_framework": CoverageOverride.FRAMEWORK_ATTACK,
        "d3fend_framework": CoverageOverride.FRAMEWORK_D3FEND,
        "object_tactic": CoverageOverride.OBJECT_TACTIC,
        "object_technique": CoverageOverride.OBJECT_TECHNIQUE,
        "object_category": CoverageOverride.OBJECT_CATEGORY,
    }
