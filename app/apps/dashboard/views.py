from datetime import date
from io import BytesIO

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import render

from apps.dashboard.dashboard import (
    build_dashboard_context,
    build_d3fend_daily_chart,
    build_executive_dashboard_context,
)
from apps.usecases.permissions import can_access_usecases
from apps.dashboard.reports import build_dashboard_pdf
from apps.reports.models import ReportDownload
from apps.reports.services import report_template_config

_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."
_MITRE_DETAIL_PAGE_SIZE = 6
_MITRE_DETAIL_PANELS = {
    "tactic_coverage": {
        "context_key": "tactic_coverage_rows",
        "title": "Cobertura por tactica ATT&CK",
        "sortable": True,
    },
    "d3fend_coverage": {
        "context_key": "d3fend_detect_coverage_rows",
        "title": "Cobertura D3FEND Detect",
        "sortable": True,
    },
    "uncovered_attacks": {
        "context_key": "uncovered_attacks",
        "title": "Tecnicas ATT&CK sin cobertura productiva",
        "sortable": False,
    },
    "uncovered_d3fends": {
        "context_key": "uncovered_d3fends",
        "title": "Tecnicas D3FEND sin cobertura ATT&CK productiva",
        "sortable": False,
    },
}


def _mitre_detail_panel(context, panel_name, *, page=1, sort="desc"):
    config = _MITRE_DETAIL_PANELS[panel_name]
    rows = list(context.get(config["context_key"], []))
    normalized_sort = sort if config["sortable"] and sort in {"asc", "desc"} else "desc"

    if config["sortable"]:
        def row_name(row):
            return f'{row.get("code", "")} {row.get("name", "")}'.casefold()

        if normalized_sort == "asc":
            rows.sort(key=lambda row: (float(row.get("percent", 0)), row_name(row)))
        else:
            rows.sort(key=lambda row: (-float(row.get("percent", 0)), row_name(row)))

    page_obj = Paginator(rows, _MITRE_DETAIL_PAGE_SIZE).get_page(page)
    return {
        "name": panel_name,
        "title": config["title"],
        "sortable": config["sortable"],
        "sort": normalized_sort,
        "page_obj": page_obj,
    }


@login_required
def dashboard_view(request):
    context = build_executive_dashboard_context(request)
    context["report_template"] = report_template_config(ReportDownload.TYPE_EXECUTIVE)
    return render(request, "dashboard_executive.html", context)


@login_required
def dashboard_mitre_view(request):
    context = build_dashboard_context(request)
    timeline_days = int(context["selected_timeline"])
    context["d3fend_daily_chart"] = build_d3fend_daily_chart(context, days=timeline_days)
    context["mitre_detail_panels"] = [
        _mitre_detail_panel(context, panel_name)
        for panel_name in _MITRE_DETAIL_PANELS
    ]
    return render(request, "dashboard.html", context)


@login_required
def dashboard_mitre_details_view(request):
    panel_name = request.GET.get("panel", "")
    if panel_name not in _MITRE_DETAIL_PANELS:
        return HttpResponseBadRequest("Panel de detalle invalido.")

    context = build_dashboard_context(request)
    detail = _mitre_detail_panel(
        context,
        panel_name,
        page=request.GET.get("page", 1),
        sort=request.GET.get("sort", "desc"),
    )
    return render(request, "includes/mitre_detail_panel.html", {"detail": detail})


@login_required
def dashboard_pdf_export(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    context = build_dashboard_context(request)
    buffer = BytesIO()
    build_dashboard_pdf(buffer, context, report_template_config(ReportDownload.TYPE_MITRE), request.user)
    response = HttpResponse(buffer.getvalue(), content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="dashboard-soc-{date.today():%Y%m%d}.pdf"'
    return response
