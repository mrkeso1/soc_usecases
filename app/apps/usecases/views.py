from collections import Counter
from datetime import date, timedelta, datetime
import csv
from io import BytesIO

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.db import OperationalError, ProgrammingError, transaction
from django.db.models import Q
from django.http import HttpResponse, JsonResponse, HttpResponseForbidden, QueryDict
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from .dashboard import build_dashboard_context
from .forms import UseCaseForm
from .lifecycle import current_lifecycle_window
from .models import D3Fend, LifecycleReview, MitreAttack, UseCase, UseCaseChangeLog
from .permissions import (
    can_access_usecases,
    can_add_usecases,
    can_assign_lifecycle_owner,
    can_delete_usecases,
    can_finish_lifecycle_review,
    can_manage_usecases,
    is_lifecycle_admin as user_is_lifecycle_admin,
)
from .reports import build_dashboard_pdf, get_active_dashboard_report_settings


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_filtered_usecases(request, *, with_prefetch: bool = True):
    qs = UseCase.objects.all()
    if with_prefetch:
        qs = qs.prefetch_related("mitre_attacks", "d3fends")

    q                 = request.GET.get("q", "").strip()
    status            = request.GET.get("status", "").strip()
    device            = request.GET.get("device", "").strip()
    severity          = request.GET.get("severity", "").strip()
    enabled           = request.GET.get("enabled", "").strip()
    owner             = request.GET.get("owner", "").strip()
    review_state      = request.GET.get("review_state", "").strip()
    mapping_attack    = request.GET.get("mapping_attack", "").strip()
    mapping_d3fend    = request.GET.get("mapping_d3fend", "").strip()
    mitre_id          = request.GET.get("mitre_id", "").strip()
    d3fend_id         = request.GET.get("d3fend_id", "").strip()
    quick             = request.GET.get("quick", "").strip()

    if q:
        qs = qs.filter(name__icontains=q)
    if status:
        qs = qs.filter(status__iexact=status)
    if device:
        qs = qs.filter(device__iexact=device)
    if severity:
        qs = qs.filter(severity__iexact=severity)
    if enabled == "yes":
        qs = qs.filter(is_enabled=True)
    elif enabled == "no":
        qs = qs.filter(is_enabled=False)
    if owner:
        qs = qs.filter(owner_name__iexact=owner)

    today      = date.today()
    soon_limit = today + timedelta(days=30)

    if review_state == "overdue":
        qs = qs.filter(next_review_date__lt=today)
    elif review_state == "soon":
        qs = qs.filter(next_review_date__gte=today, next_review_date__lte=soon_limit)
    elif review_state == "no_date":
        qs = qs.filter(next_review_date__isnull=True)

    if mapping_attack == "with":
        qs = qs.filter(mitre_attacks__isnull=False)
    elif mapping_attack == "without":
        qs = qs.filter(mitre_attacks__isnull=True)

    if mapping_d3fend == "with":
        qs = qs.filter(d3fends__isnull=False)
    elif mapping_d3fend == "without":
        qs = qs.filter(d3fends__isnull=True)

    if mitre_id.isdigit():
        qs = qs.filter(mitre_attacks__id=int(mitre_id))
    if d3fend_id.isdigit():
        qs = qs.filter(d3fends__id=int(d3fend_id))

    if quick == "overdue":
        qs = qs.filter(next_review_date__lt=today)
    elif quick == "soon":
        qs = qs.filter(next_review_date__gte=today, next_review_date__lte=soon_limit)
    elif quick == "without_attack":
        qs = qs.filter(mitre_attacks__isnull=True)
    elif quick == "without_d3fend":
        qs = qs.filter(d3fends__isnull=True)

    return qs.distinct()


def _redirect_usecase_list_with_query(return_qs: str = ""):
    query = QueryDict(return_qs, mutable=True)
    query.pop("saved_only", None)
    query.pop("updated_ids", None)
    query.pop("updated", None)

    query_string = query.urlencode()
    base_url = reverse("usecase_list")
    return redirect(f"{base_url}?{query_string}" if query_string else base_url)



def _parse_csv_ids(raw_value: str) -> list[int]:
    if not raw_value:
        return []
    return [int(x) for x in raw_value.split(",") if x.strip().isdigit()]


def _serialize_mitre(usecase) -> str:
    return ", ".join(
        f"{item.external_id} - {item.name}" if item.name else str(item.external_id)
        for item in usecase.mitre_attacks.all().order_by("external_id", "name")
    )


def _serialize_d3fend(usecase) -> str:
    return ", ".join(
        f"{item.code} - {item.name}" if item.name else str(item.code)
        for item in usecase.d3fends.all().order_by("code", "name")
    )


def _snapshot_usecase(usecase) -> dict:
    """Capture all tracked fields into a flat dict for change-log comparison."""
    return {
        "name":                 usecase.name,
        "group_name":           usecase.group_name,
        "device":               usecase.device,
        "case_type":            usecase.case_type,
        "objective":            usecase.objective,
        "blocking_type":        usecase.blocking_type,
        "owner_name":           usecase.owner_name,
        "lifecycle_control_owner": usecase.lifecycle_control_owner_id,
        "monitoring":           usecase.monitoring,
        "status":               usecase.status,
        "severity":             usecase.severity,
        "escalation":           usecase.escalation,
        "sent_to_ho":           usecase.sent_to_ho,
        "ho_flag":              usecase.ho_flag,
        "validation_status":    usecase.validation_status,
        "validation_result":    usecase.validation_result,
        "last_validation_date": usecase.last_validation_date,
        "next_review_date":     usecase.next_review_date,
        "is_enabled":           usecase.is_enabled,
        "comments":             usecase.comments,
        "mitre_attacks":        _serialize_mitre(usecase),
        "d3fends":              _serialize_d3fend(usecase),
    }


TRACKED_FIELD_LABELS = {
    "name":                 "Nombre",
    "group_name":           "Grupo",
    "device":               "Dispositivo",
    "case_type":            "Tipo",
    "objective":            "Objetivo",
    "blocking_type":        "Tipo de bloqueo",
    "owner_name":           "Responsable desarrollo",
    "lifecycle_control_owner": "Responsable control",
    "monitoring":           "Monitoreo",
    "status":               "Estado",
    "severity":             "Severidad",
    "escalation":           "Escalamiento",
    "sent_to_ho":           "Envío HO",
    "ho_flag":              "HO",
    "validation_status":    "Estado validación",
    "validation_result":    "Resultado validación",
    "last_validation_date": "Última validación",
    "next_review_date":     "Próxima revisión",
    "is_enabled":           "Habilitado",
    "comments":             "Comentarios",
    "mitre_attacks":        "ATT&CK",
    "d3fends":              "D3FEND",
}


def create_change_logs(usecase, old_data: dict, new_data: dict, user) -> None:
    for field in TRACKED_FIELD_LABELS:
        old_val = "" if old_data.get(field) is None else str(old_data[field])
        new_val = "" if new_data.get(field) is None else str(new_data[field])
        if old_val != new_val:
            UseCaseChangeLog.objects.create(
                use_case=usecase,
                field_name=field,
                old_value=old_val,
                new_value=new_val,
                changed_by=user if getattr(user, "is_authenticated", False) else None,
            )


def _parse_date_field(raw: str):
    """Parse a YYYY-MM-DD string, returning a date or None."""
    if raw:
        try:
            return datetime.strptime(raw, "%Y-%m-%d").date()
        except ValueError:
            pass
    return None


# ── Views ─────────────────────────────────────────────────────────────────────

@login_required
def dashboard_view(request):
    return render(request, "dashboard.html", build_dashboard_context(request))


@login_required
def dashboard_pdf_export(request):
    context = build_dashboard_context(request)
    report_settings = get_active_dashboard_report_settings()
    buffer = BytesIO()
    build_dashboard_pdf(buffer, context, report_settings, request.user)
    response = HttpResponse(buffer.getvalue(), content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="dashboard-soc-{date.today():%Y%m%d}.pdf"'
    return response


@login_required
def usecase_list(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden("Solo el grupo ReadOnly puede acceder al dashboard.")

    legacy_query = request.GET.copy()
    legacy_query.pop("saved_only", None)
    legacy_query.pop("updated_ids", None)
    legacy_query.pop("updated", None)
    if legacy_query.urlencode() != request.GET.urlencode():
        return _redirect_usecase_list_with_query(legacy_query.urlencode())

    qs = _get_filtered_usecases(request, with_prefetch=True)

    q                 = request.GET.get("q", "").strip()
    status            = request.GET.get("status", "").strip()
    device            = request.GET.get("device", "").strip()
    severity          = request.GET.get("severity", "").strip()
    enabled           = request.GET.get("enabled", "").strip()
    owner             = request.GET.get("owner", "").strip()
    review_state      = request.GET.get("review_state", "").strip()
    mapping_attack    = request.GET.get("mapping_attack", "").strip()
    mapping_d3fend    = request.GET.get("mapping_d3fend", "").strip()
    mitre_id          = request.GET.get("mitre_id", "").strip()
    d3fend_id         = request.GET.get("d3fend_id", "").strip()
    quick             = request.GET.get("quick", "").strip()

    selected_view = request.GET.get("view", "compact").strip()
    if selected_view not in ("compact", "detailed"):
        selected_view = "compact"

    selected_sort = request.GET.get("sort", "name").strip()
    selected_dir  = request.GET.get("dir", "asc").strip()
    if selected_dir not in ("asc", "desc"):
        selected_dir = "asc"

    sort_map = {
        "name":                 "name",
        "device":               "device",
        "owner":                "owner_name",
        "status":               "status",
        "severity":             "severity",
        "last_validation_date": "last_validation_date",
        "next_review_date":     "next_review_date",
        "enabled":              "is_enabled",
    }
    sort_field = sort_map.get(selected_sort, "name")
    if selected_dir == "desc":
        sort_field = f"-{sort_field}"
    qs = qs.order_by(sort_field, "name")

    statuses = (
        UseCase.objects.exclude(status="")
        .values_list("status", flat=True).distinct().order_by("status")
    )
    devices = (
        UseCase.objects.exclude(device="")
        .values_list("device", flat=True).distinct().order_by("device")
    )
    owners = (
        UseCase.objects.exclude(owner_name="")
        .values_list("owner_name", flat=True).distinct().order_by("owner_name")
    )

    selected_mitre  = MitreAttack.objects.filter(id=int(mitre_id)).first() if mitre_id.isdigit() else None
    selected_d3fend = D3Fend.objects.filter(id=int(d3fend_id)).first() if d3fend_id.isdigit() else None

    today      = date.today()
    soon_limit = today + timedelta(days=30)

    visible_total         = qs.count()
    visible_overdue       = qs.filter(next_review_date__lt=today).count()
    visible_soon          = qs.filter(next_review_date__gte=today, next_review_date__lte=soon_limit).count()
    visible_without_attack = qs.filter(mitre_attacks__isnull=True).distinct().count()
    visible_without_d3fend = qs.filter(d3fends__isnull=True).distinct().count()

    qs = list(qs)
    for usecase in qs:
        usecase.can_manage_by_user = can_manage_usecases(request.user, usecase)
        usecase.can_delete_by_user = can_delete_usecases(request.user, usecase)

    context = {
        "usecases":                   qs,
        "q":                          q,
        "selected_status":            status,
        "selected_device":            device,
        "selected_severity":          severity,
        "selected_enabled":           enabled,
        "selected_owner":             owner,
        "selected_review_state":      review_state,
        "selected_mapping_attack":    mapping_attack,
        "selected_mapping_d3fend":    mapping_d3fend,
        "selected_mitre":             selected_mitre,
        "selected_d3fend":            selected_d3fend,
        "selected_view":              selected_view,
        "selected_sort":              selected_sort,
        "selected_dir":               selected_dir,
        "selected_quick":             quick,
        "statuses":                   statuses,
        "devices":                    devices,
        "owners":                     owners,
        "severity_choices":           UseCase.SEVERITY_CHOICES,
        "visible_total":              visible_total,
        "visible_overdue":            visible_overdue,
        "visible_soon":               visible_soon,
        "visible_without_attack":     visible_without_attack,
        "visible_without_d3fend":     visible_without_d3fend,
        "can_add_usecases":           can_add_usecases(request.user),
        "can_manage_usecases":        any(uc.can_manage_by_user for uc in qs),
        "can_delete_usecases":        any(uc.can_delete_by_user for uc in qs),
    }
    return render(request, "usecases/usecase_list.html", context)


@login_required
def export_usecases_csv(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden("Solo el grupo ReadOnly puede acceder al dashboard.")

    qs = _get_filtered_usecases(request, with_prefetch=True).order_by("name")

    response = HttpResponse(content_type="text/csv; charset=utf-8-sig")
    response["Content-Disposition"] = 'attachment; filename="usecases_export.csv"'

    writer = csv.writer(response)
    writer.writerow([
        "Nombre", "Dispositivo", "Responsable desarrollo", "Estado", "Severidad",
        "Ultimo control", "Proximo control", "Habilitado", "ATT&CK", "D3FEND",
    ])

    for uc in qs:
        writer.writerow([
            uc.name,
            uc.device,
            uc.owner_name,
            uc.status,
            uc.severity,
            uc.last_validation_date or "",
            uc.next_review_date or "",
            "Si" if uc.is_enabled else "No",
            _serialize_mitre(uc),
            _serialize_d3fend(uc),
        ])

    return response


@login_required
def usecase_create(request):
    if not can_add_usecases(request.user):
        return HttpResponseForbidden("No tenés permisos para crear casos de uso.")

    if request.method == "POST":
        form = UseCaseForm(request.POST)
        if form.is_valid():
            usecase = form.save(commit=False)
            usecase.created_by = request.user
            usecase.updated_by = request.user
            if not usecase.owner_name:
                usecase.owner_name = request.user.get_full_name() or request.user.username
            usecase.save()
            form.save_m2m()
            messages.success(request, "Caso de uso creado correctamente.")
            return redirect("usecase_detail", pk=usecase.pk)
    else:
        form = UseCaseForm()

    return render(
        request,
        "usecases/usecase_form.html",
        {"form": form, "title": "Nuevo caso de uso"},
    )


@login_required
def usecase_edit(request, pk):
    if not _can_manage_usecases(request.user):
        return HttpResponseForbidden("No tenés permisos para editar casos de uso.")

    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends"), pk=pk
    )
    if not can_manage_usecases(request.user, usecase):
        return HttpResponseForbidden("Solo podés editar casos de uso propios.")

    old_data = _snapshot_usecase(usecase)

    if request.method == "POST":
        form = UseCaseForm(request.POST, instance=usecase)
        if form.is_valid():
            usecase = form.save(commit=False)
            usecase.updated_by = request.user
            usecase.save()
            form.save_m2m()
            new_data = _snapshot_usecase(usecase)
            create_change_logs(usecase, old_data, new_data, request.user)
            messages.success(request, "Caso de uso actualizado correctamente.")
            return redirect("usecase_detail", pk=usecase.pk)
    else:
        form = UseCaseForm(instance=usecase)

    return render(
        request,
        "usecases/usecase_form.html",
        {"form": form, "title": "Editar caso de uso", "usecase": usecase},
    )


@login_required
def usecase_detail(request, pk):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden("Solo el grupo ReadOnly puede acceder al dashboard.")

    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends", "change_logs__changed_by"),
        pk=pk,
    )
    change_logs = usecase.change_logs.all().order_by("-changed_at")
    return render(
        request,
        "usecases/usecase_detail.html",
        {
            "usecase": usecase,
            "change_logs": change_logs,
            "can_manage_usecases": can_manage_usecases(request.user, usecase),
            "can_delete_usecases": can_delete_usecases(request.user, usecase),
        },
    )


@login_required
def usecase_quick_update(request, pk):
    if not _can_manage_usecases(request.user):
        return HttpResponseForbidden("No tenés permisos para actualizar casos de uso.")

    if request.method != "POST":
        return redirect("usecase_list")

    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends"), pk=pk
    )
    if not can_manage_usecases(request.user, usecase):
        return HttpResponseForbidden("Solo podés actualizar casos de uso propios.")

    old_data = _snapshot_usecase(usecase)

    usecase.owner_name        = request.POST.get("owner_name", "").strip()
    usecase.status            = request.POST.get("status", "").strip()
    usecase.severity          = request.POST.get("severity", "").strip()
    usecase.validation_status = request.POST.get("validation_status", "").strip()
    usecase.validation_result = request.POST.get("validation_result", "").strip()
    usecase.last_validation_date = _parse_date_field(
        request.POST.get("last_validation_date", "").strip()
    )
    usecase.is_enabled  = request.POST.get("is_enabled") == "on"
    usecase.updated_by  = request.user
    usecase.save()

    usecase.mitre_attacks.set(
        MitreAttack.objects.filter(id__in=_parse_csv_ids(request.POST.get("mitre_attack_ids", "")))
    )
    usecase.d3fends.set(
        D3Fend.objects.filter(id__in=_parse_csv_ids(request.POST.get("d3fend_ids", "")))
    )

    new_data = _snapshot_usecase(usecase)
    create_change_logs(usecase, old_data, new_data, request.user)
    messages.success(request, f"Se actualizó '{usecase.name}'.")
    return redirect("usecase_list")


@login_required
def usecase_bulk_update(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden("Solo el grupo ReadOnly puede acceder al dashboard.")

    if request.method != "POST":
        return redirect("usecase_list")

    return_qs = request.POST.get("return_qs", "").strip()
    if "changed_ids" in request.POST:
        usecase_ids = _parse_csv_ids(request.POST.get("changed_ids", ""))
    else:
        raw_ids = request.POST.getlist("uc_ids")
        usecase_ids = [int(x) for x in raw_ids if str(x).isdigit()]

    if not usecase_ids:
        messages.info(request, "No se detectaron cambios para guardar.")
        return _redirect_usecase_list_with_query(return_qs)

    usecases = (
        UseCase.objects
        .filter(pk__in=usecase_ids)
        .prefetch_related("mitre_attacks", "d3fends")
        .order_by("name")
    )

    updated_count = 0
    with transaction.atomic():
        for usecase in usecases:
            if not can_manage_usecases(request.user, usecase):
                continue

            pk = str(usecase.pk)
            old_data = _snapshot_usecase(usecase)

            scalar_changes = {
                "owner_name": request.POST.get(f"owner_name_{pk}", "").strip(),
                "status": request.POST.get(f"status_{pk}", "").strip(),
                "severity": request.POST.get(f"severity_{pk}", "").strip(),
                "last_validation_date": _parse_date_field(
                    request.POST.get(f"last_validation_date_{pk}", "").strip()
                ),
                "is_enabled": request.POST.get(f"is_enabled_{pk}") == "on",
            }
            if f"validation_status_{pk}" in request.POST:
                scalar_changes["validation_status"] = request.POST.get(
                    f"validation_status_{pk}", ""
                ).strip()
            if f"validation_result_{pk}" in request.POST:
                scalar_changes["validation_result"] = request.POST.get(
                    f"validation_result_{pk}", ""
                ).strip()

            changed_fields = []
            for field_name, new_value in scalar_changes.items():
                if getattr(usecase, field_name) != new_value:
                    setattr(usecase, field_name, new_value)
                    changed_fields.append(field_name)

            current_mitre_ids = {item.id for item in usecase.mitre_attacks.all()}
            current_d3fend_ids = {item.id for item in usecase.d3fends.all()}
            posted_mitre_ids = set(_parse_csv_ids(request.POST.get(f"mitre_attack_ids_{pk}", "")))
            posted_d3fend_ids = set(_parse_csv_ids(request.POST.get(f"d3fend_ids_{pk}", "")))

            m2m_changed = False
            if current_mitre_ids != posted_mitre_ids:
                usecase.mitre_attacks.set(MitreAttack.objects.filter(id__in=posted_mitre_ids))
                m2m_changed = True
            if current_d3fend_ids != posted_d3fend_ids:
                usecase.d3fends.set(D3Fend.objects.filter(id__in=posted_d3fend_ids))
                m2m_changed = True

            if changed_fields:
                usecase.updated_by = request.user
                usecase.save()

            if changed_fields or m2m_changed:
                if m2m_changed and not changed_fields:
                    usecase.updated_by = request.user
                    usecase.save(update_fields=["updated_by", "updated_at"])
                new_data = _snapshot_usecase(usecase)
                create_change_logs(usecase, old_data, new_data, request.user)
                updated_count += 1

    if updated_count:
        messages.success(request, f"Se actualizaron {updated_count} caso(s).")
        return _redirect_usecase_list_with_query(return_qs)

    messages.info(request, "No se detectaron cambios para guardar.")
    return _redirect_usecase_list_with_query(return_qs)


@login_required
def mitre_attack_autocomplete(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden("Solo el grupo ReadOnly puede acceder al dashboard.")

    q  = request.GET.get("q", "").strip()
    qs = MitreAttack.objects.filter(is_enabled=True)
    if q:
        qs = qs.filter(
            Q(external_id__icontains=q) | Q(name__icontains=q) | Q(tactic__icontains=q)
        )
    data = [
        {
            "id":          obj.id,
            "label":       f"{obj.external_id} - {obj.name}",
            "external_id": obj.external_id,
            "name":        obj.name,
            "tactic":      obj.tactic,
        }
        for obj in qs.order_by("external_id", "name")[:20]
    ]
    return JsonResponse({"results": data})


@login_required
def d3fend_autocomplete(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden("Solo el grupo ReadOnly puede acceder al dashboard.")

    q  = request.GET.get("q", "").strip()
    qs = D3Fend.objects.filter(is_enabled=True)
    if q:
        qs = qs.filter(
            Q(code__icontains=q) | Q(name__icontains=q) | Q(category__icontains=q)
        )
    data = [
        {
            "id":       obj.id,
            "label":    f"{obj.code} - {obj.name}",
            "code":     obj.code,
            "name":     obj.name,
            "category": obj.category,
        }
        for obj in qs.order_by("code", "name")[:20]
    ]
    return JsonResponse({"results": data})


@login_required
def lifecycle_management_view(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden("Solo el grupo ReadOnly puede acceder al dashboard.")

    today = date.today()
    cycle_start, cycle_end = current_lifecycle_window(today)
    only_pending = request.GET.get("only_pending") == "1"

    lifecycle_admin = user_is_lifecycle_admin(request.user)
    usecases = UseCase.objects.select_related("lifecycle_control_owner").all().order_by("name")

    User = get_user_model()
    lifecycle_users = (
        User.objects.filter(is_active=True).order_by("username")
        if lifecycle_admin
        else User.objects.none()
    )
    rows = []
    completed_in_cycle = 0
    owner_pending_counter = Counter()

    for uc in usecases:
        last_check = uc.last_validation_date
        completed = bool(last_check and cycle_start <= last_check <= cycle_end)
        if completed:
            completed_in_cycle += 1

        review_days = uc.days_until_review
        if review_days is None:
            review_badge = "Sin fecha"
            review_level = "neutral"
        elif review_days < 0:
            review_badge = f"Vencido ({abs(review_days)}d)"
            review_level = "danger"
        elif review_days <= 15:
            review_badge = f"Por vencer ({review_days}d)"
            review_level = "warn"
        else:
            review_badge = f"Al día ({review_days}d)"
            review_level = "ok"

        is_pending = not completed
        if is_pending:
            if uc.lifecycle_control_owner:
                owner_key = uc.lifecycle_control_owner.get_full_name() or uc.lifecycle_control_owner.username
            else:
                owner_key = "Sin responsable de control"
            owner_pending_counter[owner_key] += 1

        if only_pending and not is_pending:
            continue

        rows.append({
            "usecase": uc,
            "last_check": last_check,
            "next_check": uc.next_review_date,
            "owner": uc.lifecycle_control_owner,
            "task_status": "Finalizada" if completed else "Pendiente",
            "is_pending": is_pending,
            "can_finish": can_finish_lifecycle_review(request.user, uc),
            "can_assign_owner": can_assign_lifecycle_owner(request.user),
            "review_badge": review_badge,
            "review_level": review_level,
        })

    total = usecases.count()
    pending = total - completed_in_cycle
    days_left = (cycle_end - today).days

    context = {
        "rows": rows,
        "cycle_start": cycle_start,
        "cycle_end": cycle_end,
        "summary_total": total,
        "summary_completed": completed_in_cycle,
        "summary_pending": pending,
        "summary_days_left": days_left,
        "only_pending": only_pending,
        "owner_pending_summary": owner_pending_counter.most_common(5),
        "lifecycle_users": lifecycle_users,
        "can_manage_lifecycle": lifecycle_admin,
        "lifecycle_scope_label": "Todos los casos" if lifecycle_admin else "Todos los casos · solo podés finalizar los asignados a vos",
    }
    return render(request, "usecases/lifecycle_management.html", context)


@login_required
def lifecycle_mark_done(request, pk):
    if request.method != 'POST':
        return redirect('lifecycle_management')

    uc = get_object_or_404(UseCase, pk=pk)
    if not can_finish_lifecycle_review(request.user, uc):
        return HttpResponseForbidden("Solo el responsable de control asignado o un administrador puede finalizar esta revisión.")

    old_data = _snapshot_usecase(uc)
    if can_assign_lifecycle_owner(request.user):
        owner_id = request.POST.get("lifecycle_control_owner", "").strip()
        if owner_id.isdigit():
            uc.lifecycle_control_owner_id = int(owner_id)
        elif owner_id == "":
            uc.lifecycle_control_owner = None

    uc.last_validation_date = date.today()
    uc.validation_status = "Finalizado"
    uc.updated_by = request.user
    uc.save()

    LifecycleReview.objects.create(
        use_case=uc,
        control_owner=uc.lifecycle_control_owner,
        completed_by=request.user,
        status=uc.validation_status,
        result=uc.validation_result,
        checked_at=uc.last_validation_date,
        next_review_date=uc.next_review_date,
    )
    create_change_logs(uc, old_data, _snapshot_usecase(uc), request.user)
    messages.success(request, f"Ciclo de vida actualizado para '{uc.name}'.")
    return redirect('lifecycle_management')


@login_required
def lifecycle_assign_owner(request, pk):
    if request.method != "POST":
        return redirect("lifecycle_management")

    if not can_assign_lifecycle_owner(request.user):
        return HttpResponseForbidden("Solo administradores pueden reasignar responsables de control.")

    uc = get_object_or_404(UseCase, pk=pk)
    old_data = _snapshot_usecase(uc)
    owner_id = request.POST.get("lifecycle_control_owner", "").strip()
    if owner_id.isdigit():
        uc.lifecycle_control_owner_id = int(owner_id)
    else:
        uc.lifecycle_control_owner = None
    uc.updated_by = request.user
    uc.save()
    create_change_logs(uc, old_data, _snapshot_usecase(uc), request.user)
    messages.success(request, f"Responsable de control actualizado para '{uc.name}'.")
    return redirect("lifecycle_management")


@login_required
def usecase_delete(request, pk):
    if request.method != "POST":
        return redirect("usecase_detail", pk=pk)

    usecase = get_object_or_404(UseCase, pk=pk)
    if not can_delete_usecases(request.user, usecase):
        return HttpResponseForbidden("Solo podés eliminar casos de uso propios si tenés permiso de borrado.")

    name = usecase.name
    usecase.delete()
    messages.success(request, f"Caso de uso '{name}' eliminado.")
    return redirect("usecase_list")
