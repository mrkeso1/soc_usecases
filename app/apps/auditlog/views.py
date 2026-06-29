from django.contrib.auth.decorators import login_required
import csv
from io import BytesIO

from django.http import Http404, HttpResponse
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, render
from openpyxl import Workbook

from .models import AuditLog
from .timeline import ACTION_LABELS, AREA_ALL, allowed_audit_areas, build_audit_timeline_context, get_timeline_item


def _can_view_audit(user):
    return len(allowed_audit_areas(user) - {AREA_ALL}) > 0


def _can_export_audit(user):
    return (
        getattr(user, "is_superuser", False)
        or getattr(user, "is_staff", False)
        or user.groups.filter(name="Admin").exists()
        or user.has_perm("auditlog.export_audit")
    )


@login_required
def audit_list(request):
    if not _can_view_audit(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")

    context = build_audit_timeline_context(request.GET, user=request.user)
    context["can_export_audit"] = _can_export_audit(request.user)
    return render(request, "auditlog/audit_list.html", context)


@login_required
def audit_detail(request, pk):
    if not _can_view_audit(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")
    if "security" not in allowed_audit_areas(request.user):
        return HttpResponseForbidden("No tenes permisos para ver auditoria de seguridad.")
    item = get_object_or_404(AuditLog.objects.select_related("actor"), pk=pk)
    item.action_label = ACTION_LABELS.get(item.action, item.action.replace("_", " ").capitalize())
    return render(request, "auditlog/audit_detail.html", {"item": item})


@login_required
def audit_timeline_detail(request, source, pk):
    if not _can_view_audit(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")
    item = get_timeline_item(source, pk)
    if item is None:
        raise Http404("Evento de auditoria no encontrado")
    if item.area not in allowed_audit_areas(request.user):
        return HttpResponseForbidden("No tenes permisos para ver esta auditoria.")
    return render(request, "auditlog/audit_detail.html", {"item": item, "timeline_detail": True})


def _export_rows(request):
    context = build_audit_timeline_context(request.GET, user=request.user, paginate=False)
    rows = [[
        "Fecha",
        "Area",
        "Accion",
        "Actor",
        "Entidad",
        "ID entidad",
        "Resumen",
        "IP",
        "Origen",
    ]]
    for item in context["items"]:
        rows.append([
            item.occurred_at.strftime("%Y-%m-%d %H:%M:%S"),
            item.area_label,
            item.action_label,
            str(item.actor or "Sistema"),
            item.entity_type,
            item.entity_id,
            item.summary,
            item.ip_address,
            item.source,
        ])
    return rows


@login_required
def audit_export_csv(request):
    if not _can_view_audit(request.user) or not _can_export_audit(request.user):
        return HttpResponseForbidden("No tenes permisos para exportar auditoria.")

    response = HttpResponse(content_type="text/csv; charset=utf-8-sig")
    response["Content-Disposition"] = 'attachment; filename="auditoria.csv"'
    writer = csv.writer(response)
    writer.writerows(_export_rows(request))
    return response


@login_required
def audit_export_xlsx(request):
    if not _can_view_audit(request.user) or not _can_export_audit(request.user):
        return HttpResponseForbidden("No tenes permisos para exportar auditoria.")

    wb = Workbook()
    ws = wb.active
    ws.title = "Auditoria"
    for row in _export_rows(request):
        ws.append(row)
    buffer = BytesIO()
    wb.save(buffer)
    response = HttpResponse(
        buffer.getvalue(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = 'attachment; filename="auditoria.xlsx"'
    return response
