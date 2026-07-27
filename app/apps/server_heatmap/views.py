import csv

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .connectors.siem import SiemCsvConnector
from .classification import active_naming_rules, apply_automatic_classification
from .forms import (
    InventoryConfigurationForm,
    ServerAssetForm,
    ServerCategoryForm,
    ServerNamingRuleForm,
)
from .models import (
    InventoryObservation,
    InventorySyncRun,
    ReconciliationIssue,
    ServerAsset,
    ServerCategory,
    ServerInventoryConfiguration,
    ServerNamingRule,
)
from .network_diagnostics import diagnose_ingestion_gaps
from .permissions import can_access_server_heatmap, can_manage_server_heatmap
from .reconciliation import reprocess_stored_inventory, synchronize_inventory


MAX_SIEM_UPLOAD_BYTES = 15 * 1024 * 1024


def _percent(part, total):
    return round(part / total * 100, 1) if total else 0.0


def _coverage_level(percent, ad_count, total):
    if not total:
        return "empty"
    if not ad_count:
        return "no_baseline"
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
        qs = qs.filter(category_id=type_filter)
    if coverage_filter == "both":
        qs = qs.filter(in_active_directory=True, in_siem=True)
    elif coverage_filter == "ad_only":
        qs = qs.filter(in_active_directory=True, in_siem=False)
    elif coverage_filter == "siem_only":
        qs = qs.filter(in_active_directory=False, in_siem=True)
    elif coverage_filter:
        coverage_filter = ""

    os_labels = dict(ServerAsset.OS_CHOICES)
    os_keys = [key for key, _ in ServerAsset.OS_CHOICES]
    categories = list(
        ServerCategory.objects.filter(is_active=True).order_by("order", "name")
    )
    cells_data = {
        (item["os_family"], item["category_id"]): item
        for item in qs.values("os_family", "category_id").annotate(
            total=Count("id"),
            ad_count=Count("id", filter=Q(in_active_directory=True)),
            siem_count=Count("id", filter=Q(in_siem=True)),
            covered_count=Count(
                "id",
                filter=Q(in_active_directory=True, in_siem=True),
            ),
        )
    }
    os_totals = {
        item["os_family"]: item["total"]
        for item in qs.values("os_family").annotate(total=Count("id"))
    }

    matrix_rows = []
    for os_key in os_keys:
        cells = []
        for category in categories:
            data = cells_data.get((os_key, category.id), {})
            total = data.get("total", 0)
            ad_count = data.get("ad_count", 0)
            siem_count = data.get("siem_count", 0)
            covered_count = data.get("covered_count", 0)
            gap_count = ad_count - covered_count
            coverage_percent = _percent(covered_count, ad_count) if ad_count else None
            cells.append({
                "os": os_key,
                "category": category,
                "total": total,
                "ad_count": ad_count,
                "siem_count": siem_count,
                "covered_count": covered_count,
                "gap_count": gap_count,
                "coverage_percent": coverage_percent,
                "level": _coverage_level(coverage_percent, ad_count, total),
            })
        matrix_rows.append({
            "key": os_key,
            "label": os_labels[os_key],
            "total": os_totals.get(os_key, 0),
            "cells": cells,
        })

    def grouped_coverage(field, labels=None, *, exclude_empty=False):
        grouped = qs.filter(in_active_directory=True)
        if exclude_empty:
            grouped = grouped.exclude(**{f"{field}__isnull": True})
            if field == "application_name":
                grouped = grouped.exclude(application_name="")
        data = {
            item[field]: item
            for item in grouped.values(field).annotate(
                ad_count=Count("id"),
                covered_count=Count("id", filter=Q(in_siem=True)),
            )
        }
        return [
            {
                "key": key,
                "label": (labels or {}).get(key, key or "Sin identificar"),
                "ad_count": values["ad_count"],
                "covered_count": values["covered_count"],
                "gap_count": values["ad_count"] - values["covered_count"],
                "percent": _percent(values["covered_count"], values["ad_count"]),
            }
            for key, values in data.items()
        ]

    summary = qs.aggregate(
        total=Count("id"),
        ad_count=Count("id", filter=Q(in_active_directory=True)),
        siem_count=Count("id", filter=Q(in_siem=True)),
        both_count=Count("id", filter=Q(in_active_directory=True, in_siem=True)),
        ad_only_count=Count("id", filter=Q(in_active_directory=True, in_siem=False)),
        siem_only_count=Count("id", filter=Q(in_active_directory=False, in_siem=True)),
    )
    gaps_qs = qs.filter(in_active_directory=True, in_siem=False)
    gap_summary = gaps_qs.aggregate(
        total=Count("id"),
        dns_resolved=Count("id", filter=Q(dns_status=ServerAsset.DNS_RESOLVED)),
        reachable=Count(
            "id",
            filter=Q(reachability_status=ServerAsset.REACHABILITY_REACHABLE),
        ),
        unreachable=Count(
            "id",
            filter=Q(reachability_status=ServerAsset.REACHABILITY_UNREACHABLE),
        ),
    )
    gaps = list(gaps_qs.select_related("category").order_by("hostname")[:50])
    latest_siem_run = InventorySyncRun.objects.filter(
        source=InventorySyncRun.SOURCE_SIEM,
        status=InventorySyncRun.STATUS_SUCCESS,
    ).first()
    latest_ad_run = InventorySyncRun.objects.filter(
        source=InventorySyncRun.SOURCE_AD,
        status=InventorySyncRun.STATUS_SUCCESS,
    ).first()
    unmatched_siem = []
    unresolved_issue_counts = {
        ReconciliationIssue.TYPE_AMBIGUOUS: 0,
        ReconciliationIssue.TYPE_MISSING_IDENTIFIER: 0,
        ReconciliationIssue.TYPE_NOT_IN_AD: 0,
    }
    if latest_siem_run:
        for item in latest_siem_run.issues.filter(is_resolved=False).values(
            "issue_type",
        ).annotate(total=Count("id")):
            unresolved_issue_counts[item["issue_type"]] = item["total"]
        unmatched_siem = list(
            InventoryObservation.objects.filter(
                sync_run=latest_siem_run,
                asset__isnull=True,
                issues__is_resolved=False,
            ).distinct().order_by("hostname", "external_id")[:50]
        )

    category_labels = {category.id: category.name for category in categories}
    os_coverage_data = {
        item["key"]: item
        for item in grouped_coverage("os_family", os_labels)
    }
    category_coverage_data = {
        item["key"]: item
        for item in grouped_coverage("category_id", category_labels, exclude_empty=True)
    }
    return {
        "matrix_rows": matrix_rows,
        "matrix_types": categories,
        "os_rows": [
            os_coverage_data.get(key, {
                "key": key, "label": label, "ad_count": 0,
                "covered_count": 0, "gap_count": 0, "percent": 0.0,
            })
            for key, label in ServerAsset.OS_CHOICES
        ],
        "type_rows": [
            category_coverage_data.get(category.id, {
                "key": category.id, "label": category.name, "ad_count": 0,
                "covered_count": 0, "gap_count": 0, "percent": 0.0,
            })
            for category in categories
        ],
        "application_rows": sorted(grouped_coverage(
            "application_name",
            exclude_empty=True,
        ), key=lambda item: (-item["ad_count"], str(item["label"]))),
        "gaps": gaps,
        "gap_total": gap_summary["total"],
        "dns_resolved_count": gap_summary["dns_resolved"],
        "reachable_count": gap_summary["reachable"],
        "unreachable_count": gap_summary["unreachable"],
        "latest_siem_run": latest_siem_run,
        "latest_ad_run": latest_ad_run,
        "unmatched_siem": unmatched_siem,
        "unresolved_issue_counts": unresolved_issue_counts,
        "unmatched_siem_count": sum(unresolved_issue_counts.values()),
        "total_assets": summary["total"],
        "ad_count": summary["ad_count"],
        "siem_count": summary["siem_count"],
        "both_count": summary["both_count"],
        "ad_only_count": summary["ad_only_count"],
        "siem_only_count": summary["siem_only_count"],
        "siem_coverage_percent": _percent(summary["both_count"], summary["ad_count"]),
        "os_choices": ServerAsset.OS_CHOICES,
        "type_choices": ServerCategory.objects.filter(is_active=True),
        "selected_os": os_filter,
        "selected_type": type_filter,
        "selected_coverage": coverage_filter,
        "selected_enabled": enabled_filter,
    }


@login_required
def server_heatmap_view(request):
    if not can_access_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para acceder al mapa de servidores.")
    context = build_server_heatmap_context(request.GET)
    context["can_manage_inventory"] = can_manage_server_heatmap(request.user)
    return render(request, "server_heatmap/dashboard.html", context)


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
            asset.category.name if asset.category else asset.get_server_type_display(),
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


@login_required
@require_POST
def reprocess_inventory(request):
    if not can_access_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para reprocesar el inventario.")
    result = reprocess_stored_inventory()
    messages.success(
        request,
        f"Inventario reprocesado sin consultar AD ni cargar CSV: "
        f"{result['processed']} observaciones cruzadas y {result['matched']} asociadas.",
    )
    return redirect("server_heatmap")


@login_required
def server_administration(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar el inventario.")

    configuration = ServerInventoryConfiguration.load()
    configuration_form = InventoryConfigurationForm(instance=configuration)
    rule_form = ServerNamingRuleForm(prefix="rule")
    category_form = ServerCategoryForm(prefix="category")
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "save_configuration":
            configuration_form = InventoryConfigurationForm(request.POST, instance=configuration)
            if configuration_form.is_valid():
                configuration_form.save()
                messages.success(request, "Configuración del inventario actualizada.")
                return redirect("server_heatmap_administration")
        elif action == "create_rule":
            rule_form = ServerNamingRuleForm(request.POST, prefix="rule")
            if rule_form.is_valid():
                rule_form.save()
                messages.success(request, "Regla de nomenclatura creada.")
                return redirect("server_heatmap_administration")
        elif action == "create_category":
            category_form = ServerCategoryForm(request.POST, prefix="category")
            if category_form.is_valid():
                category_form.save()
                messages.success(request, "Sección de servidores creada.")
                return redirect("server_heatmap_administration")
        elif action in {"enable_assets", "disable_assets", "reclassify_assets"}:
            asset_ids = request.POST.getlist("asset_ids")
            assets = ServerAsset.objects.filter(id__in=asset_ids)
            if action == "enable_assets":
                changed = assets.update(is_enabled=True)
                messages.success(request, f"{changed} equipo(s) habilitado(s).")
            elif action == "disable_assets":
                changed = assets.update(is_enabled=False)
                messages.success(request, f"{changed} equipo(s) deshabilitado(s).")
            else:
                rules = active_naming_rules()
                changed = 0
                for asset in assets.filter(classification_source=ServerAsset.CLASSIFICATION_AUTO):
                    apply_automatic_classification(asset, rules=rules)
                    changed += 1
                messages.success(request, f"{changed} equipo(s) reclasificado(s).")
            return redirect(request.get_full_path())
        elif action == "resolve_issues":
            issue_ids = request.POST.getlist("issue_ids")
            changed = ReconciliationIssue.objects.filter(
                id__in=issue_ids,
                is_resolved=False,
            ).update(is_resolved=True)
            messages.success(request, f"{changed} conflicto(s) marcado(s) como resuelto(s).")
            return redirect("server_heatmap_administration")

    query = (request.GET.get("q") or "").strip()
    enabled = (request.GET.get("enabled") or "all").strip()
    server_type = (request.GET.get("type") or "").strip()
    assets = ServerAsset.objects.all()
    if query:
        assets = assets.filter(
            Q(hostname__icontains=query)
            | Q(ip_address__icontains=query)
            | Q(application_name__icontains=query)
            | Q(organizational_unit__icontains=query)
        )
    if enabled == "yes":
        assets = assets.filter(is_enabled=True)
    elif enabled == "no":
        assets = assets.filter(is_enabled=False)
    if server_type:
        assets = assets.filter(category_id=server_type)
    page = Paginator(assets.order_by("hostname"), 100).get_page(request.GET.get("page"))

    return render(
        request,
        "server_heatmap/administration.html",
        {
            "configuration_form": configuration_form,
            "rule_form": rule_form,
            "category_form": category_form,
            "categories": ServerCategory.objects.all(),
            "rules": ServerNamingRule.objects.all(),
            "asset_page": page,
            "runs": InventorySyncRun.objects.all()[:10],
            "unresolved_issues": ReconciliationIssue.objects.filter(
                is_resolved=False,
            ).select_related("sync_run", "observation").order_by("-created_at")[:100],
            "query": query,
            "selected_enabled": enabled,
            "selected_type": server_type,
            "type_choices": ServerCategory.objects.filter(is_active=True),
        },
    )


@login_required
def edit_naming_rule(request, rule_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    rule = get_object_or_404(ServerNamingRule, pk=rule_id)
    form = ServerNamingRuleForm(request.POST or None, instance=rule)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Regla de nomenclatura actualizada.")
        return redirect("server_heatmap_administration")
    return render(
        request,
        "server_heatmap/rule_form.html",
        {"form": form, "rule": rule},
    )


@login_required
@require_POST
def delete_naming_rule(request, rule_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    rule = get_object_or_404(ServerNamingRule, pk=rule_id)
    name = rule.name
    rule.delete()
    messages.success(request, f"Regla «{name}» eliminada.")
    return redirect("server_heatmap_administration")


@login_required
def edit_server_asset(request, asset_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar equipos.")
    asset = get_object_or_404(ServerAsset, pk=asset_id)
    form = ServerAssetForm(request.POST or None, instance=asset)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, f"Equipo {asset.hostname} actualizado.")
        return redirect("server_heatmap_administration")
    return render(
        request,
        "server_heatmap/asset_form.html",
        {"form": form, "asset": asset},
    )


@login_required
def edit_server_category(request, category_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar secciones.")
    category = get_object_or_404(ServerCategory, pk=category_id)
    form = ServerCategoryForm(request.POST or None, instance=category)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Sección de servidores actualizada.")
        return redirect("server_heatmap_administration")
    return render(
        request,
        "server_heatmap/category_form.html",
        {"form": form, "category": category},
    )


@login_required
@require_POST
def delete_server_category(request, category_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar secciones.")
    category = get_object_or_404(ServerCategory, pk=category_id)
    if category.assets.exists() or category.naming_rules.exists():
        messages.error(request, "No se puede eliminar una sección que está siendo utilizada.")
    else:
        name = category.name
        category.delete()
        messages.success(request, f"Sección «{name}» eliminada.")
    return redirect("server_heatmap_administration")
