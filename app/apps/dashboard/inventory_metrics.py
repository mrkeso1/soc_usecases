from datetime import timedelta

from django.core.paginator import Paginator
from django.db.models import F, Q
from django.utils import timezone

from apps.server_heatmap.models import (
    ServerAsset,
    ServerCategory,
    ServerInventoryConfiguration,
)


INVENTORY_LIST_MODES = {"new", "pending", "completed", "overdue"}


def _bounded_integer(value, default, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return min(max(parsed, minimum), maximum)


def _duration_label(value):
    if value is None:
        return "Sin fecha"
    total_minutes = max(int(value.total_seconds() // 60), 0)
    days, remaining_minutes = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(remaining_minutes, 60)
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min"


def _asset_row(asset, now, sla_days):
    discovered_at = asset.ad_first_seen_at or asset.created_at
    if asset.in_siem and asset.siem_first_seen_at and discovered_at:
        elapsed = asset.siem_first_seen_at - discovered_at
        status = "Ingestado"
        status_class = "good"
    else:
        elapsed = now - discovered_at if discovered_at else None
        status = "Pendiente"
        status_class = "bad"
    return {
        "asset": asset,
        "discovered_at": discovered_at,
        "elapsed_label": _duration_label(elapsed),
        "status": status,
        "status_class": status_class,
        "sla_overdue": bool(
            not asset.in_siem
            and discovered_at
            and discovered_at < now - timedelta(days=sla_days)
        ),
    }


def build_inventory_dashboard_context(request, *, now=None):
    now = now or timezone.now()
    configuration = ServerInventoryConfiguration.load()
    params = request.GET

    period_days = _bounded_integer(
        params.get("inventory_period"),
        configuration.dashboard_period_days,
        1,
        365,
    )
    page_size = _bounded_integer(
        params.get("inventory_page_size"),
        configuration.dashboard_page_size,
        10,
        100,
    )
    environment = (
        params.get("inventory_environment")
        or configuration.dashboard_default_environment
        or "PROD"
    ).strip()
    criticality = params.get("inventory_criticality", "all")
    if criticality not in {"all", "critical", "standard"}:
        criticality = "all"
    ping_status = params.get("inventory_ping", "all")
    valid_ping_statuses = {key for key, _label in ServerAsset.REACHABILITY_CHOICES}
    if ping_status != "all" and ping_status not in valid_ping_statuses:
        ping_status = "all"
    category_id = params.get("inventory_category", "")
    if category_id:
        try:
            category_id = str(int(category_id))
        except (TypeError, ValueError):
            category_id = ""
    search = params.get("inventory_q", "").strip()
    list_mode = params.get("inventory_list", "pending")
    if list_mode not in INVENTORY_LIST_MODES:
        list_mode = "pending"

    assets = ServerAsset.objects.filter(in_active_directory=True).select_related("category")
    if configuration.dashboard_enabled_only:
        assets = assets.filter(is_enabled=True, is_excluded_by_rule=False)
    if environment.casefold() != "all":
        assets = assets.filter(environment__iexact=environment)
    else:
        environment = "all"
    if criticality == "critical":
        assets = assets.filter(is_critical=True)
    elif criticality == "standard":
        assets = assets.filter(is_critical=False)
    if category_id:
        assets = assets.filter(category_id=category_id)
    if ping_status != "all":
        assets = assets.filter(reachability_status=ping_status)
    if search:
        assets = assets.filter(
            Q(hostname__icontains=search)
            | Q(display_name__icontains=search)
            | Q(ip_address__icontains=search)
            | Q(organizational_unit__icontains=search)
        )

    period_start = now - timedelta(days=period_days)
    sla_cutoff = now - timedelta(days=configuration.ingestion_sla_days)
    new_assets = assets.filter(ad_first_seen_at__gte=period_start)
    pending_assets = assets.filter(in_siem=False)
    completed_assets = assets.filter(
        ad_first_seen_at__gte=period_start,
        ad_first_seen_at__isnull=False,
        siem_first_seen_at__isnull=False,
        siem_first_seen_at__gte=F("ad_first_seen_at"),
    )
    overdue_assets = pending_assets.filter(
        ad_first_seen_at__isnull=False,
        ad_first_seen_at__lt=sla_cutoff,
    )

    latencies = [
        siem_first_seen - ad_first_seen
        for ad_first_seen, siem_first_seen in completed_assets.values_list(
            "ad_first_seen_at", "siem_first_seen_at"
        )
    ]
    average_latency = (
        sum(latencies, timedelta()) / len(latencies)
        if latencies
        else None
    )

    if list_mode == "new":
        list_queryset = new_assets.order_by(F("ad_first_seen_at").desc(nulls_last=True), "hostname")
        list_title = f"Servidores encontrados en los últimos {period_days} días"
    elif list_mode == "completed":
        list_queryset = completed_assets.order_by(F("siem_first_seen_at").desc(nulls_last=True), "hostname")
        list_title = f"Servidores ingestados de la cohorte de {period_days} días"
    elif list_mode == "overdue":
        list_queryset = overdue_assets.order_by(F("ad_first_seen_at").asc(nulls_last=True), "hostname")
        list_title = f"Pendientes fuera del SLA de {configuration.ingestion_sla_days} días"
    else:
        list_queryset = pending_assets.order_by(F("ad_first_seen_at").asc(nulls_last=True), "hostname")
        list_title = "Servidores con falta de ingesta"

    page_obj = Paginator(list_queryset, page_size).get_page(params.get("inventory_page", 1))
    inventory_rows = [
        _asset_row(asset, now, configuration.ingestion_sla_days)
        for asset in page_obj.object_list
    ]
    period_choices = sorted({7, 14, 30, 90, configuration.dashboard_period_days, period_days})
    environment_choices = sorted({
        value.strip().upper()
        for value in ServerAsset.objects.exclude(environment="")
        .values_list("environment", flat=True)
        if value.strip()
    })

    return {
        "inventory_new_count": new_assets.count(),
        "inventory_pending_count": pending_assets.count(),
        "inventory_completed_count": completed_assets.count(),
        "inventory_overdue_count": overdue_assets.count(),
        "inventory_average_ingestion": (
            _duration_label(average_latency)
            if average_latency is not None
            else "—"
        ),
        "inventory_sla_days": configuration.ingestion_sla_days,
        "inventory_period_days": period_days,
        "inventory_period_choices": period_choices,
        "inventory_environment_choices": environment_choices,
        "inventory_category_choices": ServerCategory.objects.filter(is_active=True).order_by("order", "name"),
        "inventory_ping_choices": ServerAsset.REACHABILITY_CHOICES,
        "selected_inventory_environment": environment,
        "selected_inventory_criticality": criticality,
        "selected_inventory_category": category_id,
        "selected_inventory_ping": ping_status,
        "inventory_search": search,
        "inventory_list_mode": list_mode,
        "inventory_list_title": list_title,
        "inventory_rows": inventory_rows,
        "inventory_page_obj": page_obj,
        "inventory_page_size": page_size,
        "inventory_enabled_only": configuration.dashboard_enabled_only,
    }
