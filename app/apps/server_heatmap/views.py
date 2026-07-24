from collections import Counter
import csv

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from .connectors.siem import SiemCsvConnector
from .models import InventoryObservation, InventorySyncRun, ServerAsset
from .network_diagnostics import diagnose_ingestion_gaps
from .permissions import can_access_server_heatmap
from .reconciliation import synchronize_inventory


MAX_SIEM_UPLOAD_BYTES = 15 * 1024 * 1024


def _percent(part, total):
    return round(part / total * 100, 1) if total else 0.0


def _coverage_level(percent, total):
    if not total:
        return "empty"
    if percent >= 90:
        return "good"
    if percent >= 70:
        return "medium"
    if percent > 0:
        return "warning"
    return "bad"


def build_server_heatmap_context(params):
    os_filter = (params.get("os") or "").strip()
    type_filter = (params.get("type") or "").strip()
    coverage_filter = (params.get("coverage") or "").strip()
    enabled_filter = (params.get("enabled") or "yes").strip()

    qs = ServerAsset.objects.all()
    if enabled_filter == "yes":
        qs = qs.filter(is_enabled=True)
    elif enabled_filter == "no":
        qs = qs.filter(is_enabled=False)
    elif enabled_filter != "all":
        enabled_filter = "yes"
        qs = qs.filter(is_enabled=True)
    if os_filter:
        qs = qs.filter(os_family=os_filter)
    if type_filter:
        qs = qs.filter(server_type=type_filter)
    if coverage_filter == "both":
        qs = qs.filter(in_active_directory=True, in_siem=True)
    elif coverage_filter == "ad_only":
        qs = qs.filter(in_active_directory=True, in_siem=False)
    elif coverage_filter == "siem_only":
        qs = qs.filter(in_active_directory=False, in_siem=True)
    elif coverage_filter:
        coverage_filter = ""

    assets = list(qs.order_by("hostname"))
    os_labels = dict(ServerAsset.OS_CHOICES)
    type_labels = dict(ServerAsset.SERVER_TYPE_CHOICES)
    os_keys = [key for key, _ in ServerAsset.OS_CHOICES if any(item.os_family == key for item in assets)]
    type_keys = [key for key, _ in ServerAsset.SERVER_TYPE_CHOICES if any(item.server_type == key for item in assets)]

    matrix_rows = []
    for os_key in os_keys:
        cells = []
        row_assets = [item for item in assets if item.os_family == os_key]
        for server_type in type_keys:
            cell_assets = [item for item in row_assets if item.server_type == server_type]
            ad_count = sum(item.in_active_directory for item in cell_assets)
            siem_count = sum(item.in_siem for item in cell_assets)
            covered_count = sum(item.in_active_directory and item.in_siem for item in cell_assets)
            gap_count = sum(item.in_active_directory and not item.in_siem for item in cell_assets)
            coverage_percent = _percent(covered_count, ad_count)
            cells.append({
                "os": os_key,
                "server_type": server_type,
                "total": len(cell_assets),
                "ad_count": ad_count,
                "siem_count": siem_count,
                "covered_count": covered_count,
                "gap_count": gap_count,
                "coverage_percent": coverage_percent,
                "level": _coverage_level(coverage_percent, len(cell_assets)),
            })
        matrix_rows.append({"key": os_key, "label": os_labels[os_key], "total": len(row_assets), "cells": cells})

    def breakdown(field, labels=None, source_assets=None):
        source_assets = assets if source_assets is None else source_assets
        counts = Counter(getattr(item, field) for item in source_assets)
        maximum = max(counts.values(), default=0)
        return [
            {
                "key": key,
                "label": (labels or {}).get(key, key or "Sin identificar"),
                "value": value,
                "percent": _percent(value, len(source_assets)),
                "bar_percent": _percent(value, maximum),
            }
            for key, value in sorted(counts.items(), key=lambda item: (-item[1], str(item[0])))
        ]

    ad_count = sum(item.in_active_directory for item in assets)
    siem_count = sum(item.in_siem for item in assets)
    both_count = sum(item.in_active_directory and item.in_siem for item in assets)
    ad_only_count = sum(item.in_active_directory and not item.in_siem for item in assets)
    siem_only_count = sum(not item.in_active_directory and item.in_siem for item in assets)
    gaps = [item for item in assets if item.in_active_directory and not item.in_siem]
    dns_resolved_count = sum(item.dns_status == ServerAsset.DNS_RESOLVED for item in gaps)
    reachable_count = sum(
        item.reachability_status == ServerAsset.REACHABILITY_REACHABLE
        for item in gaps
    )
    unreachable_count = sum(
        item.reachability_status == ServerAsset.REACHABILITY_UNREACHABLE
        for item in gaps
    )
    latest_siem_run = InventorySyncRun.objects.filter(
        source=InventorySyncRun.SOURCE_SIEM,
    ).first()
    latest_ad_run = InventorySyncRun.objects.filter(
        source=InventorySyncRun.SOURCE_AD,
    ).first()
    unmatched_siem = []
    if latest_siem_run:
        unmatched_siem = list(
            InventoryObservation.objects.filter(
                sync_run=latest_siem_run,
                asset__isnull=True,
            ).order_by("hostname", "external_id")[:50]
        )

    return {
        "assets": assets,
        "matrix_rows": matrix_rows,
        "matrix_types": [{"key": key, "label": type_labels[key]} for key in type_keys],
        "os_rows": breakdown("os_family", os_labels),
        "type_rows": breakdown("server_type", type_labels),
        "application_rows": breakdown("application_name", source_assets=[item for item in assets if item.application_name]),
        "gaps": gaps[:50],
        "gap_total": len(gaps),
        "dns_resolved_count": dns_resolved_count,
        "reachable_count": reachable_count,
        "unreachable_count": unreachable_count,
        "latest_siem_run": latest_siem_run,
        "latest_ad_run": latest_ad_run,
        "unmatched_siem": unmatched_siem,
        "unmatched_siem_count": latest_siem_run.issues_count if latest_siem_run else 0,
        "total_assets": len(assets),
        "ad_count": ad_count,
        "siem_count": siem_count,
        "both_count": both_count,
        "ad_only_count": ad_only_count,
        "siem_only_count": siem_only_count,
        "siem_coverage_percent": _percent(both_count, ad_count),
        "os_choices": ServerAsset.OS_CHOICES,
        "type_choices": ServerAsset.SERVER_TYPE_CHOICES,
        "selected_os": os_filter,
        "selected_type": type_filter,
        "selected_coverage": coverage_filter,
        "selected_enabled": enabled_filter,
    }


@login_required
def server_heatmap_view(request):
    if not can_access_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para acceder al mapa de servidores.")
    return render(request, "server_heatmap/dashboard.html", build_server_heatmap_context(request.GET))


@login_required
@require_POST
def upload_siem_inventory(request):
    if not can_access_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para actualizar el inventario SIEM.")
    uploaded = request.FILES.get("siem_csv")
    if not uploaded:
        messages.error(request, "Seleccioná el CSV exportado desde el SIEM.")
        return redirect("server_heatmap")
    if not uploaded.name.lower().endswith(".csv"):
        messages.error(request, "El archivo del SIEM debe tener extensión .csv.")
        return redirect("server_heatmap")
    if uploaded.size > MAX_SIEM_UPLOAD_BYTES:
        messages.error(request, "El CSV supera el límite permitido de 15 MB.")
        return redirect("server_heatmap")

    raw = uploaded.read()
    text = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        messages.error(request, "No se pudo interpretar la codificación del CSV.")
        return redirect("server_heatmap")

    try:
        run = synchronize_inventory(
            InventorySyncRun.SOURCE_SIEM,
            SiemCsvConnector(text=text),
            metadata={"filename": uploaded.name, "uploaded_by": request.user.get_username()},
        )
    except Exception as exc:
        messages.error(request, f"No se pudo procesar el CSV SIEM: {exc}")
        return redirect("server_heatmap")

    covered = ServerAsset.objects.filter(in_active_directory=True, in_siem=True, is_enabled=True).count()
    gaps = ServerAsset.objects.filter(in_active_directory=True, in_siem=False, is_enabled=True).count()
    messages.success(
        request,
        f"CSV SIEM procesado: {run.records_read} registros, {covered} equipos AD cubiertos, "
        f"{gaps} pendientes de ingesta y {run.issues_count} registros sin asociación AD.",
    )
    return redirect("server_heatmap")


@login_required
def export_ingestion_gaps(request):
    if not can_access_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para exportar las brechas.")
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="servidores_pendientes_ingesta.csv"'
    response.write("\ufeff")
    writer = csv.writer(response, delimiter=";")
    writer.writerow([
        "Hostname", "IP", "Sistema operativo", "Tipo", "Aplicación", "Ambiente", "OU",
        "DNS", "IP resuelta", "Ping", "Última actividad AD", "Resultado",
    ])
    queryset = ServerAsset.objects.filter(
        is_enabled=True,
        in_active_directory=True,
        in_siem=False,
    ).order_by("hostname")
    for asset in queryset:
        writer.writerow([
            asset.hostname,
            asset.ip_address or "",
            asset.os_name or asset.get_os_family_display(),
            asset.get_server_type_display(),
            asset.application_name,
            asset.environment,
            asset.organizational_unit,
            asset.get_dns_status_display(),
            asset.resolved_ip_address or "",
            asset.get_reachability_status_display(),
            asset.ad_last_logon_at.isoformat() if asset.ad_last_logon_at else "",
            asset.diagnostic_result,
        ])
    return response


@login_required
@require_POST
def diagnose_gaps(request):
    if not can_access_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para diagnosticar los equipos.")
    result = diagnose_ingestion_gaps(
        limit=200,
        workers=16,
        timeout=2,
        only_unchecked=True,
    )
    remaining = ServerAsset.objects.filter(
        is_enabled=True,
        in_active_directory=True,
        in_siem=False,
        network_checked_at__isnull=True,
    ).count()
    messages.success(
        request,
        f"Diagnóstico finalizado: {result['checked']} equipos, "
        f"{result['dns_resolved']} resolvieron DNS y {result['reachable']} respondieron ping. "
        f"Quedan {remaining} sin verificar.",
    )
    return redirect("server_heatmap")
