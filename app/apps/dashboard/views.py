from datetime import date
from io import BytesIO

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import render

from apps.dashboard.dashboard import build_dashboard_context, build_executive_dashboard_context
from apps.usecases.permissions import can_access_usecases
from apps.dashboard.reports import build_dashboard_pdf
from apps.reports.models import ReportDownload
from apps.reports.services import report_template_config

_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."


@login_required
def dashboard_view(request):
    context = build_executive_dashboard_context(request)
    context["report_template"] = report_template_config(ReportDownload.TYPE_EXECUTIVE)
    return render(request, "dashboard_executive.html", context)


@login_required
def dashboard_mitre_view(request):
    return render(request, "dashboard.html", build_dashboard_context(request))


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
