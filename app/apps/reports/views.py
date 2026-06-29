from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.clickjacking import xframe_options_sameorigin

from apps.auditlog.service import audit
from apps.lifecycle.lifecycle import lifecycle_state, mark_report_export, report_key_for_period
from apps.usecases.permissions import resolve_user_roles

from .forms import ReportTemplateConfigForm
from .models import ReportDownload
from .services import (
    REPORT_DEFINITIONS,
    REPORT_SECTION_CHOICES,
    build_report_pdf,
    default_sections,
    report_filename,
    report_index_context,
    report_template_config,
)


_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."


def _can_access_reports(user):
    roles = resolve_user_roles(user)
    if roles["is_admin"] or roles["is_analyst"]:
        return True
    if roles["is_readonly"]:
        return False
    return user.has_perm("reports.view_reportdownload")


def _can_export_reports(user):
    roles = resolve_user_roles(user)
    if roles["is_admin"] or roles["is_analyst"]:
        return True
    if roles["is_readonly"]:
        return False
    return user.has_perm("reports.export_reports")


def _can_configure_templates(user):
    roles = resolve_user_roles(user)
    if roles["is_admin"]:
        return True
    return user.has_perm("reports.configure_report_templates")


@login_required
def report_index(request):
    if not _can_access_reports(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    context = report_index_context()
    context["can_configure_templates"] = _can_configure_templates(request.user)
    return render(request, "reports/report_index.html", context)


@login_required
def report_preview(request, report_type):
    if report_type not in REPORT_DEFINITIONS:
        raise Http404("Reporte no encontrado")
    if not _can_access_reports(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    config = report_template_config(report_type)
    enabled_sections = set(config.sections or default_sections(report_type))
    return render(request, "reports/report_preview.html", {
        "report_type": report_type,
        "definition": REPORT_DEFINITIONS[report_type],
        "config": config,
        "sections": REPORT_SECTION_CHOICES.get(report_type, []),
        "enabled_sections": enabled_sections,
        "preview_pdf_url": f"{request.path}pdf/",
        "can_export_reports": _can_export_reports(request.user),
        "can_configure_templates": _can_configure_templates(request.user),
    })


@login_required
@xframe_options_sameorigin
def report_preview_pdf(request, report_type):
    if report_type not in REPORT_DEFINITIONS:
        raise Http404("Reporte no encontrado")
    if not _can_access_reports(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    filename = report_filename(report_type)
    response = HttpResponse(build_report_pdf(report_type, request), content_type="application/pdf")
    response["Content-Disposition"] = f'inline; filename="{filename}"'
    return response


@login_required
def report_template_settings(request):
    if not _can_configure_templates(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    report_type = request.POST.get("report_type") or request.GET.get("report_type") or ReportDownload.TYPE_EXECUTIVE
    if report_type not in REPORT_DEFINITIONS:
        report_type = ReportDownload.TYPE_EXECUTIVE
    config = report_template_config(report_type)
    form = ReportTemplateConfigForm(
        request.POST or None,
        request.FILES or None,
        instance=config,
        report_type=report_type,
    )
    if request.method == "POST" and form.is_valid():
        item = form.save(commit=False)
        item.report_type = report_type
        item.updated_by = request.user
        if form.cleaned_data.get("remove_logo"):
            item.logo = None
        item.save()
        form.save_m2m()
        audit(request, "report_template_updated", "ReportTemplateConfig", item.pk, {"report_type": report_type})
        return redirect("report_preview", report_type=report_type)
    return render(request, "reports/template_settings.html", {
        "form": form,
        "report_type": report_type,
        "report_types": ReportDownload.TYPE_CHOICES,
        "config": config,
    })


def _mark_lifecycle_report_if_needed(requested_key=""):
    state = lifecycle_state(None)
    exports = state.get("report_exports", {})
    available_keys = {
        report_key_for_period(period["period"])
        for period in state["periods"]
        if period["complete"]
    }
    if state["annual_ready"]:
        available_keys.add("annual")
    if requested_key in available_keys and not exports.get(requested_key):
        mark_report_export(state["year"], requested_key)
        return requested_key
    for period in state["periods"]:
        key = report_key_for_period(period["period"])
        if period["complete"] and not exports.get(key):
            mark_report_export(state["year"], key)
            return key
    if state["annual_ready"] and not exports.get("annual"):
        mark_report_export(state["year"], "annual")
        return "annual"
    return ""


@login_required
def report_download(request, report_type):
    if report_type not in REPORT_DEFINITIONS:
        raise Http404("Reporte no encontrado")
    if not _can_export_reports(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    filename = report_filename(report_type)
    pdf = build_report_pdf(report_type, request)
    record = ReportDownload.objects.create(
        report_type=report_type,
        filename=filename,
        generated_by=request.user,
    )
    lifecycle_report_key = ""
    if report_type == ReportDownload.TYPE_LIFECYCLE:
        lifecycle_report_key = _mark_lifecycle_report_if_needed(request.GET.get("lifecycle_report_key", ""))
    audit(
        request,
        "report_download",
        "ReportDownload",
        record.pk,
        {
            "report_type": report_type,
            "filename": filename,
            "lifecycle_report_key": lifecycle_report_key,
        },
    )
    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
