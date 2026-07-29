import csv

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.auditlog.rate_limits import database_rate_limit
from apps.auditlog.service import audit, client_ip

from .connectors.siem import SiemCsvConnector
from .classification import active_classification_rules, apply_automatic_classification
from .forms import (
    InventoryConfigurationForm,
    InventoryFilterRuleForm,
    ServerAssetForm,
    ServerCategoryForm,
)
from .models import (
    InventoryObservation,
    InventoryFilterRule,
    InventoryJob,
    InventoryRuleRevision,
    InventorySyncRun,
    ReconciliationIssue,
    ServerAsset,
    ServerAssetDisableEvent,
    ServerCategory,
    ServerInventoryConfiguration,
)
from .jobs import enqueue_inventory_job
from .network_diagnostics import diagnose_ingestion_gaps
from .inventory_filters import simulate_inventory_filters
from .permissions import can_access_server_heatmap, can_manage_server_heatmap
from .reconciliation import (
    retry_issue_name_resolution,
    synchronize_inventory,
)


MAX_SIEM_UPLOAD_BYTES = 15 * 1024 * 1024
HEATMAP_TABLE_PAGE_SIZE = 50
limit_inventory_sync = database_rate_limit(
    scope="server_inventory_sync",
    limit_setting="ADMIN_ACTION_RATE_LIMIT_SYNC",
    default_limit=3,
)
limit_inventory_mutation = database_rate_limit(
    scope="server_inventory_mutation",
    limit_setting="ADMIN_ACTION_RATE_LIMIT_MUTATION",
    default_limit=30,
)
RULE_REVISION_FIELD_LABELS = {
    "name": "Nombre",
    "pattern": "Patrón",
    "match_type": "Modo de coincidencia",
    "source": "Origen",
    "field": "Campo evaluado",
    "operator": "Operador",
    "action": "Acción",
    "os_family": "Sistema operativo",
    "server_type": "Tipo interno",
    "server_type_value": "Tipo interno",
    "category": "Sección funcional",
    "priority": "Prioridad",
    "is_active": "Activa",
    "environment_value": "Ambiente",
    "notes": "Notas",
    "reason": "Motivo",
}


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
    os_groups = [
        {
            "key": ServerAsset.OS_WINDOWS,
            "label": "Windows",
            "members": (ServerAsset.OS_WINDOWS,),
        },
        {
            "key": ServerAsset.OS_LINUX,
            "label": "Linux",
            "members": (ServerAsset.OS_LINUX, ServerAsset.OS_UNIX),
        },
        {
            "key": ServerAsset.OS_UNKNOWN,
            "label": "Desconocido",
            "members": (ServerAsset.OS_OTHER, ServerAsset.OS_UNKNOWN),
        },
    ]
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
    for os_group in os_groups:
        os_key = os_group["key"]
        cells = []
        for category in categories:
            grouped_data = [
                cells_data.get((member, category.id), {})
                for member in os_group["members"]
            ]
            total = sum(data.get("total", 0) for data in grouped_data)
            ad_count = sum(data.get("ad_count", 0) for data in grouped_data)
            siem_count = sum(data.get("siem_count", 0) for data in grouped_data)
            covered_count = sum(data.get("covered_count", 0) for data in grouped_data)
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
            "label": os_group["label"],
            "total": sum(os_totals.get(member, 0) for member in os_group["members"]),
            "cells": cells,
        })

    def grouped_coverage(field, labels=None, *, exclude_empty=False, base_queryset=None):
        grouped = (
            base_queryset if base_queryset is not None else qs
        ).filter(in_active_directory=True)
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
    gap_page = Paginator(
        gaps_qs.select_related("category").order_by("hostname"),
        HEATMAP_TABLE_PAGE_SIZE,
    ).get_page(params.get("gap_page"))
    latest_siem_run = InventorySyncRun.objects.filter(
        source=InventorySyncRun.SOURCE_SIEM,
        status=InventorySyncRun.STATUS_SUCCESS,
    ).first()
    latest_ad_run = InventorySyncRun.objects.filter(
        source=InventorySyncRun.SOURCE_AD,
        status=InventorySyncRun.STATUS_SUCCESS,
    ).first()
    unmatched_siem_page = None
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
        unmatched_siem_page = Paginator(
            InventoryObservation.objects.filter(
                sync_run=latest_siem_run,
                asset__isnull=True,
                issues__is_resolved=False,
            ).distinct().order_by("hostname", "external_id"),
            HEATMAP_TABLE_PAGE_SIZE,
        ).get_page(params.get("conflict_page"))

    category_labels = {category.id: category.name for category in categories}
    os_coverage_data = {
        item["key"]: item
        for item in grouped_coverage("os_family", os_labels)
    }
    windows_coverage = os_coverage_data.get(ServerAsset.OS_WINDOWS, {
        "ad_count": 0,
        "covered_count": 0,
        "gap_count": 0,
    })
    linux_members = [
        os_coverage_data.get(key, {})
        for key in (ServerAsset.OS_LINUX, ServerAsset.OS_UNIX)
    ]
    linux_ad_count = sum(item.get("ad_count", 0) for item in linux_members)
    linux_covered_count = sum(item.get("covered_count", 0) for item in linux_members)
    operating_system_rows = [
        {
            **windows_coverage,
            "key": ServerAsset.OS_WINDOWS,
            "label": "Windows",
            "percent": _percent(
                windows_coverage.get("covered_count", 0),
                windows_coverage.get("ad_count", 0),
            ),
        },
        {
            "key": ServerAsset.OS_LINUX,
            "label": "Linux / Unix / AIX",
            "ad_count": linux_ad_count,
            "covered_count": linux_covered_count,
            "gap_count": linux_ad_count - linux_covered_count,
            "percent": _percent(linux_covered_count, linux_ad_count),
        },
    ]
    category_coverage_data = {
        item["key"]: item
        for item in grouped_coverage("category_id", category_labels, exclude_empty=True)
    }
    return {
        "matrix_rows": matrix_rows,
        "matrix_types": categories,
        "os_rows": operating_system_rows,
        "type_rows": [
            category_coverage_data.get(category.id, {
                "key": category.id, "label": category.name, "ad_count": 0,
                "covered_count": 0, "gap_count": 0, "percent": 0.0,
            })
            for category in categories
        ],
        "gaps": gap_page,
        "gap_page": gap_page,
        "gap_total": gap_summary["total"],
        "dns_resolved_count": gap_summary["dns_resolved"],
        "reachable_count": gap_summary["reachable"],
        "unreachable_count": gap_summary["unreachable"],
        "latest_siem_run": latest_siem_run,
        "latest_ad_run": latest_ad_run,
        "unmatched_siem": unmatched_siem_page or (),
        "unmatched_siem_page": unmatched_siem_page,
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
@limit_inventory_sync
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
@limit_inventory_sync
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
@limit_inventory_sync
def reprocess_inventory(request):
    if not can_access_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para reprocesar el inventario.")
    job, created = enqueue_inventory_job(
        InventoryJob.TYPE_REPROCESS,
        requested_by=request.user,
        idempotency_key=request.headers.get("Idempotency-Key"),
    )
    messages.success(
        request,
        (
            f"Reproceso encolado como trabajo #{job.id}."
            if created
            else f"Ya existe un reproceso activo: trabajo #{job.id}."
        ),
    )
    return redirect("server_heatmap_administration")


@login_required
@require_POST
@limit_inventory_sync
def queue_full_inventory_sync(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para actualizar el inventario.")
    job, created = enqueue_inventory_job(
        InventoryJob.TYPE_FULL_SYNC,
        requested_by=request.user,
        idempotency_key=request.headers.get("Idempotency-Key"),
    )
    messages.success(
        request,
        (
            f"Actualización AD + SIEM encolada como trabajo #{job.id}."
            if created
            else f"Ya existe una actualización activa: trabajo #{job.id}."
        ),
    )
    return redirect("server_heatmap_administration")


@login_required
@limit_inventory_mutation
def server_administration(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar el inventario.")

    configuration = ServerInventoryConfiguration.load()
    configuration_form = InventoryConfigurationForm(instance=configuration)
    category_form = ServerCategoryForm(prefix="category")
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "save_configuration":
            configuration_form = InventoryConfigurationForm(request.POST, instance=configuration)
            if configuration_form.is_valid():
                configuration_form.save()
                messages.success(request, "Configuración del inventario actualizada.")
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
                justification = (request.POST.get("disable_justification") or "").strip()
                if not justification:
                    messages.error(request, "La justificación es obligatoria para deshabilitar equipos.")
                    return redirect(request.get_full_path())
                selected_assets = list(assets.filter(is_enabled=True))
                with transaction.atomic():
                    ServerAssetDisableEvent.objects.bulk_create([
                        ServerAssetDisableEvent(
                            asset=asset,
                            hostname=asset.hostname,
                            actor=request.user,
                            justification=justification,
                            previous_enabled=True,
                            new_enabled=False,
                            source_ip=client_ip(request) or None,
                            user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
                        )
                        for asset in selected_assets
                    ])
                    changed = ServerAsset.objects.filter(
                        id__in=[asset.id for asset in selected_assets],
                    ).update(is_enabled=False)
                    audit(
                        request,
                        "server_assets_disabled",
                        "server_asset",
                        ",".join(str(asset.id) for asset in selected_assets),
                        {
                            "justification": justification,
                            "count": changed,
                            "hostnames": [asset.hostname for asset in selected_assets],
                        },
                    )
                messages.success(request, f"{changed} equipo(s) deshabilitado(s).")
            else:
                rules = active_classification_rules()
                changed = 0
                for asset in assets:
                    apply_automatic_classification(asset, rules=rules, force=True)
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
        elif action == "resolve_issue_names":
            issues = ReconciliationIssue.objects.filter(
                id__in=request.POST.getlist("issue_ids"),
                is_resolved=False,
            ).select_related("observation")
            resolved = failed = 0
            for issue in issues:
                success, _ = retry_issue_name_resolution(issue)
                resolved += int(success)
                failed += int(not success)
            if resolved:
                messages.success(request, f"{resolved} conflicto(s) asociados mediante DNS.")
            if failed:
                messages.warning(
                    request,
                    f"{failed} conflicto(s) no pudieron resolverse; conservan el detalle del intento.",
                )
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
            "category_form": category_form,
            "categories": ServerCategory.objects.all(),
            "asset_page": page,
            "runs": InventorySyncRun.objects.all()[:10],
            "jobs": InventoryJob.objects.select_related("requested_by").all()[:15],
            "unresolved_issues": ReconciliationIssue.objects.filter(
                is_resolved=False,
            ).select_related("sync_run", "observation").order_by("-created_at")[:100],
            "query": query,
            "selected_enabled": enabled,
            "selected_type": server_type,
            "type_choices": ServerCategory.objects.filter(is_active=True),
        },
    )


def _filtered_assets(params):
    query = (params.get("q") or "").strip()
    enabled = (params.get("enabled") or "all").strip()
    server_type = (params.get("type") or "").strip()
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
    page = Paginator(assets.order_by("hostname"), 100).get_page(params.get("page"))
    return {
        "asset_page": page,
        "query": query,
        "selected_enabled": enabled,
        "selected_type": server_type,
    }


@login_required
def server_asset_results(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar equipos.")
    return render(
        request,
        "server_heatmap/_asset_results.html",
        _filtered_assets(request.GET),
    )


@login_required
@limit_inventory_mutation
def server_sections(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar secciones.")
    form = ServerCategoryForm(request.POST or None, prefix="category")
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Sección funcional creada.")
        return redirect("server_heatmap_administration")
    return render(request, "server_heatmap/sections.html", {
        "form": form,
        "categories": ServerCategory.objects.all(),
    })


@login_required
@limit_inventory_mutation
def server_naming_rules(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    messages.info(
        request,
        "Las nomenclaturas se unificaron en Reglas de inventario.",
    )
    return redirect("server_heatmap_filter_list")


@login_required
@limit_inventory_mutation
def edit_naming_rule(request, rule_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    messages.info(
        request,
        "La regla anterior fue migrada. Administrala desde Reglas de inventario.",
    )
    return redirect("server_heatmap_filter_list")


@login_required
@require_POST
@limit_inventory_mutation
def delete_naming_rule(request, rule_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    messages.info(
        request,
        "La nomenclatura anterior se conserva únicamente para rollback. "
        "Eliminá su regla migrada desde Reglas de inventario.",
    )
    return redirect("server_heatmap_filter_list")


@login_required
@limit_inventory_mutation
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
        {
            "form": form,
            "asset": asset,
            "disable_events": asset.disable_events.select_related("actor")[:20],
        },
    )


@login_required
@limit_inventory_mutation
def edit_server_category(request, category_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar secciones.")
    category = get_object_or_404(ServerCategory, pk=category_id)
    form = ServerCategoryForm(request.POST or None, instance=category)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Sección de servidores actualizada.")
        return redirect("server_heatmap_sections")
    return render(
        request,
        "server_heatmap/category_form.html",
        {"form": form, "category": category},
    )


@login_required
@require_POST
@limit_inventory_mutation
def delete_server_category(request, category_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar secciones.")
    category = get_object_or_404(ServerCategory, pk=category_id)
    name = category.name
    asset_count = category.assets.count()
    rule_count = category.naming_rules.count() + category.inventory_filter_rules.count()
    category.delete()
    messages.success(
        request,
        f"Sección «{name}» eliminada. "
        f"{asset_count} equipo(s) quedaron sin sección y "
        f"{rule_count} regla(s) quedaron sin asignación.",
    )
    return redirect("server_heatmap_sections")


@login_required
def inventory_filter_list(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    simulation = None
    if request.GET.get("simulate") == "1":
        simulation = simulate_inventory_filters()
    return render(
        request,
        "server_heatmap/filter_list.html",
        {
            "rules": InventoryFilterRule.objects.select_related("category").all(),
            "simulation": simulation,
        },
    )


@login_required
def inventory_rule_history(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para consultar el historial de reglas.")

    rule_type = (request.GET.get("type") or "").strip()
    rule_object_id = (request.GET.get("id") or "").strip()
    query = (request.GET.get("q") or "").strip()
    revisions = InventoryRuleRevision.objects.select_related("changed_by")
    if rule_type in {
        InventoryRuleRevision.TYPE_NAMING,
        InventoryRuleRevision.TYPE_FILTER,
    }:
        revisions = revisions.filter(rule_type=rule_type)
    else:
        rule_type = ""
    if rule_object_id.isdigit():
        revisions = revisions.filter(rule_object_id=int(rule_object_id))
    else:
        rule_object_id = ""
    if query:
        revisions = revisions.filter(rule_name__icontains=query)

    page = Paginator(revisions, 50).get_page(request.GET.get("page"))
    for revision in page.object_list:
        changes = []
        for field in revision.changed_fields:
            if field == "category_id" or field not in RULE_REVISION_FIELD_LABELS:
                continue
            before = revision.before_snapshot.get(field)
            after = revision.after_snapshot.get(field)
            if field == "is_active":
                before = "Sí" if before else "No" if before is not None else "—"
                after = "Sí" if after else "No" if after is not None else "—"
            else:
                before = "—" if before in (None, "") else str(before)
                after = "—" if after in (None, "") else str(after)
            changes.append({
                "label": RULE_REVISION_FIELD_LABELS[field],
                "before": before,
                "after": after,
            })
        revision.display_changes = changes

    return render(
        request,
        "server_heatmap/rule_history.html",
        {
            "page": page,
            "selected_type": rule_type,
            "selected_id": rule_object_id,
            "query": query,
        },
    )


@login_required
@limit_inventory_mutation
def inventory_filter_create(request):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    form = InventoryFilterRuleForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        rule = form.save()
        job, _ = enqueue_inventory_job(
            InventoryJob.TYPE_APPLY_FILTERS,
            requested_by=request.user,
        )
        messages.success(
            request,
            f"Regla «{rule.name}» creada {'activa' if rule.is_active else 'inactiva'}. "
            f"Aplicación automática encolada como trabajo #{job.id}.",
        )
        return redirect("server_heatmap_filter_edit", rule_id=rule.id)
    return render(
        request,
        "server_heatmap/filter_form.html",
        {"form": form, "rule": None, "preview": None},
    )


@login_required
@limit_inventory_mutation
def inventory_filter_edit(request, rule_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    rule = get_object_or_404(InventoryFilterRule, pk=rule_id)
    form = InventoryFilterRuleForm(request.POST or None, instance=rule)
    if request.method == "POST" and form.is_valid():
        form.save()
        job, _ = enqueue_inventory_job(
            InventoryJob.TYPE_APPLY_FILTERS,
            requested_by=request.user,
        )
        messages.success(
            request,
            f"Regla actualizada. Aplicación automática encolada como trabajo #{job.id}.",
        )
        return redirect("server_heatmap_filter_edit", rule_id=rule.id)
    preview = None
    if request.GET.get("preview") == "1":
        preview = simulate_inventory_filters(
            rules=InventoryFilterRule.objects.filter(pk=rule.pk),
        )
    return render(
        request,
        "server_heatmap/filter_form.html",
        {"form": form, "rule": rule, "preview": preview},
    )


@login_required
@require_POST
@limit_inventory_mutation
def inventory_filter_delete(request, rule_id):
    if not can_manage_server_heatmap(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar reglas.")
    rule = get_object_or_404(InventoryFilterRule, pk=rule_id)
    name = rule.name
    rule.delete()
    job, _ = enqueue_inventory_job(
        InventoryJob.TYPE_APPLY_FILTERS,
        requested_by=request.user,
    )
    messages.success(
        request,
        f"Regla «{name}» eliminada. "
        f"Recálculo encolado como trabajo #{job.id}.",
    )
    return redirect("server_heatmap_filter_list")
