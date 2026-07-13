from datetime import date, timedelta, datetime
import csv
from io import BytesIO, StringIO
import tempfile
from pathlib import Path

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.management import call_command
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
from django.db import models
from django.http import HttpResponse, HttpResponseForbidden, QueryDict
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from .bulk_updates import parse_csv_ids as _parse_csv_ids
from .bulk_updates import parse_posted_usecase_ids, update_usecases_bulk
from .forms import UseCaseForm, UseCaseRuleConditionFormSet
from apps.mitre.models import D3Fend, MitreAttack
from apps.sources.models import EventSource, UseCaseSource
from apps.sigma_tools.models import UseCaseTechnicalBackup
from apps.sigma_tools.services import sync_inventory_rule_backup

from .models import UseCase, UseCaseChangeLog
from .permissions import (
    can_access_usecases,
    can_add_usecases,
    can_delete_usecases,
    can_manage_usecases,
    resolve_user_roles,
)
from .snapshots import (
    serialize_d3fend as _serialize_d3fend,
    serialize_mitre as _serialize_mitre,
    snapshot_usecase as _snapshot_usecase,
)
from .text_utils import split_multi_value
from openpyxl import Workbook

_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."
PRODUCTION_STATUS = UseCase.STATUS_PRODUCTION


# Helpers


def _multi_value_filter(field_name, value):
    return (
        models.Q(**{f"{field_name}__iexact": value})
        | models.Q(**{f"{field_name}__istartswith": f"{value},"})
        | models.Q(**{f"{field_name}__icontains": f", {value},"})
        | models.Q(**{f"{field_name}__iendswith": f", {value}"})
    )


def _distinct_multi_values(queryset, field_name):
    values = []
    seen = set()
    for raw_value in queryset.exclude(**{field_name: ""}).values_list(field_name, flat=True):
        for value in split_multi_value(raw_value):
            key = value.casefold()
            if key not in seen:
                values.append(value)
                seen.add(key)
    return sorted(values, key=str.casefold)


def _get_filtered_usecases(
    request,
    *,
    with_prefetch: bool = True,
    ignore_quick: bool = False,
    production_only: bool = True,
):
    qs = UseCase.objects.filter(status__iexact=PRODUCTION_STATUS) if production_only else UseCase.objects.all()

    if with_prefetch:
        qs = qs.prefetch_related("mitre_attacks", "d3fends", "d3fend_exclusions", "source_links__source")

    q              = request.GET.get("q", "").strip()
    status_param   = request.GET.get("status")
    status         = PRODUCTION_STATUS if production_only or status_param is None else status_param.strip()
    device         = request.GET.get("device", "").strip()
    source         = request.GET.get("source", "").strip()
    severity       = request.GET.get("severity", "").strip()
    enabled        = request.GET.get("enabled", "").strip()
    owner          = request.GET.get("owner", "").strip()
    review_state   = request.GET.get("review_state", "").strip()
    mapping_attack = request.GET.get("mapping_attack", "").strip()
    mapping_d3fend = request.GET.get("mapping_d3fend", "").strip()
    mitre_id       = request.GET.get("mitre_id", "").strip()
    mitre_tactic   = request.GET.get("mitre_tactic", "").strip()
    d3fend_id      = request.GET.get("d3fend_id", "").strip()
    quick          = "" if ignore_quick else request.GET.get("quick", "").strip()

    if q:
        qs = qs.filter(
            models.Q(name__icontains=q)
            | models.Q(group_name__icontains=q)
            | models.Q(device__icontains=q)
            | models.Q(objective__icontains=q)
            | models.Q(owner_name__icontains=q)
            | models.Q(source_links__source__name__icontains=q)
            | models.Q(source_links__source__code__icontains=q)
        )
    if status and not production_only:
        qs = qs.filter(status__iexact=status)
    if device:
        qs = qs.filter(_multi_value_filter("device", device))
    if source.isdigit():
        qs = qs.filter(source_links__source_id=int(source))
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
    if mitre_tactic:
        qs = qs.filter(mitre_attacks__tactic__icontains=mitre_tactic)
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
    elif quick == "enabled":
        qs = qs.filter(is_enabled=True)
    elif quick == "critical":
        qs = qs.filter(severity__iexact="Critical")

    filters = {
        "q": q, "status": status, "device": device, "source": source, "severity": severity,
        "enabled": enabled, "owner": owner, "review_state": review_state,
        "mapping_attack": mapping_attack, "mapping_d3fend": mapping_d3fend,
        "mitre_id": mitre_id, "mitre_tactic": mitre_tactic,
        "d3fend_id": d3fend_id, "quick": quick,
    }
    return qs.distinct(), filters


def _redirect_usecase_list_with_query(return_qs: str = ""):
    query = QueryDict(return_qs, mutable=True)
    query.pop("saved_only", None)
    query.pop("updated_ids", None)
    query.pop("updated", None)

    query_string = query.urlencode()
    base_url = reverse("usecase_list")
    return redirect(f"{base_url}?{query_string}" if query_string else base_url)


def _parse_date_field(raw: str):
    if raw:
        try:
            return datetime.strptime(raw, "%Y-%m-%d").date()
        except ValueError:
            pass
    return None


def _validation_error_messages(exc: ValidationError) -> list[str]:
    if hasattr(exc, "message_dict"):
        messages = []
        for field_errors in exc.message_dict.values():
            messages.extend(str(item) for item in field_errors)
        return messages
    return [str(item) for item in exc.messages]


def _sync_usecase_sources(usecase, sources, user):
    selected_ids = {source.id for source in sources}
    current_ids = set(usecase.source_links.values_list("source_id", flat=True))

    remove_ids = current_ids - selected_ids
    if remove_ids:
        usecase.source_links.filter(source_id__in=remove_ids).delete()

    for source_id in selected_ids - current_ids:
        UseCaseSource.objects.create(
            use_case=usecase,
            source_id=source_id,
            role=UseCaseSource.ROLE_PRIMARY,
            is_required=True,
            created_by=user if getattr(user, "is_authenticated", False) else None,
        )


def _serialize_sources(usecase):
    return "; ".join(
        link.source.display_name
        for link in usecase.source_links.all()
    )


def _inventory_display_version():
    sequence = UseCaseChangeLog.objects.count()
    if sequence <= 0:
        return "0.0"
    return "1.0" if sequence == 1 else f"1.{(sequence - 1) * 2}"


def _usecase_business_rule_errors(usecase, *, mitre_ids=None):
    """Adapter para validar reglas centralizadas en UseCase.clean()."""
    sentinel = object()
    previous_mitre_ids = getattr(usecase, "_clean_mitre_attack_ids", sentinel)

    if mitre_ids is not None:
        usecase._clean_mitre_attack_ids = {
            int(item) for item in mitre_ids if str(item).isdigit()
        }

    try:
        usecase.clean()
        return []
    except ValidationError as exc:
        return _validation_error_messages(exc)
    finally:
        if mitre_ids is not None:
            if previous_mitre_ids is sentinel:
                try:
                    delattr(usecase, "_clean_mitre_attack_ids")
                except AttributeError:
                    pass
            else:
                usecase._clean_mitre_attack_ids = previous_mitre_ids



# Views

@login_required
def usecase_list(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    legacy_query = request.GET.copy()
    legacy_query.pop("saved_only", None)
    legacy_query.pop("updated_ids", None)
    legacy_query.pop("updated", None)
    if legacy_query.urlencode() != request.GET.urlencode():
        return _redirect_usecase_list_with_query(legacy_query.urlencode())

    # _get_filtered_usecases returns (queryset, filters) - unpack correctly.
    qs, filters = _get_filtered_usecases(request, with_prefetch=True, production_only=False)

    q              = filters["q"]
    status         = filters["status"]
    device         = filters["device"]
    source         = filters["source"]
    severity       = filters["severity"]
    enabled        = filters["enabled"]
    owner          = filters["owner"]
    review_state   = filters["review_state"]
    mapping_attack = filters["mapping_attack"]
    mapping_d3fend = filters["mapping_d3fend"]
    mitre_id       = filters["mitre_id"]
    mitre_tactic   = filters["mitre_tactic"]
    d3fend_id      = filters["d3fend_id"]
    quick          = filters["quick"]

    selected_view = request.GET.get("view", "compact").strip()
    if selected_view not in ("compact", "detailed"):
        selected_view = "compact"

    selected_sort = request.GET.get("sort", "name").strip()
    selected_dir  = request.GET.get("dir",  "asc").strip()
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

    devices = _distinct_multi_values(UseCase.objects.all(), "device")
    sources = EventSource.objects.filter(status=EventSource.STATUS_ACTIVE).order_by("name")
    selected_source_label = (
        EventSource.objects.filter(pk=int(source)).values_list("name", flat=True).first()
        if source.isdigit() else ""
    )
    owners = (
        UseCase.objects.exclude(owner_name="")
        .values_list("owner_name", flat=True).distinct().order_by("owner_name")
    )

    selected_mitre  = MitreAttack.objects.filter(id=int(mitre_id)).first()  if mitre_id.isdigit()  else None
    selected_d3fend = D3Fend.objects.filter(id=int(d3fend_id)).first()      if d3fend_id.isdigit() else None

    today      = date.today()
    soon_limit = today + timedelta(days=30)

    quick_base_qs, _ = _get_filtered_usecases(request, with_prefetch=False, ignore_quick=True, production_only=False)

    production_total       = UseCase.objects.filter(status__iexact=PRODUCTION_STATUS).count()
    visible_total          = qs.count()
    visible_enabled        = quick_base_qs.filter(is_enabled=True).count()
    visible_critical       = quick_base_qs.filter(severity__iexact="Critical").count()
    visible_overdue        = quick_base_qs.filter(next_review_date__lt=today).count()
    visible_soon           = quick_base_qs.filter(next_review_date__gte=today, next_review_date__lte=soon_limit).count()
    visible_without_attack = quick_base_qs.filter(mitre_attacks__isnull=True).distinct().count()
    visible_without_d3fend = quick_base_qs.filter(d3fends__isnull=True).distinct().count()

    all_filtered_count = visible_total
    paginator = Paginator(qs, 25)
    page_obj = paginator.get_page(request.GET.get("page"))
    qs = list(page_obj.object_list)

    # Resolve user roles once - avoids repeated group DB queries in the loop below.
    roles = resolve_user_roles(request.user)

    for usecase in qs:
        usecase.inferred_d3fends   = list(usecase.inferred_d3fends_queryset())
        usecase.can_manage_by_user = can_manage_usecases(request.user, usecase, _roles=roles)
        usecase.can_delete_by_user = can_delete_usecases(request.user, usecase, _roles=roles)

    context = {
        "usecases":                qs,
        "page_obj":                page_obj,
        "all_filtered_count":      all_filtered_count,
        "q":                       q,
        "selected_status":         status,
        "selected_device":         device,
        "selected_source":         source,
        "selected_source_label":   selected_source_label,
        "selected_severity":       severity,
        "selected_enabled":        enabled,
        "selected_owner":          owner,
        "selected_review_state":   review_state,
        "selected_mapping_attack": mapping_attack,
        "selected_mapping_d3fend": mapping_d3fend,
        "selected_mitre":          selected_mitre,
        "selected_mitre_tactic":   mitre_tactic,
        "selected_d3fend":         selected_d3fend,
        "selected_view":           selected_view,
        "selected_sort":           selected_sort,
        "selected_dir":            selected_dir,
        "selected_quick":          quick,
        "devices":                 devices,
        "sources":                 sources,
        "owners":                  owners,
        "severity_choices":        UseCase.SEVERITY_CHOICES,
        "status_choices":          UseCase.STATUS_CHOICES,
        "inventory_version":       _inventory_display_version(),
        "production_total":        production_total,
        "visible_total":           visible_total,
        "visible_enabled":         visible_enabled,
        "visible_critical":        visible_critical,
        "visible_overdue":         visible_overdue,
        "visible_soon":            visible_soon,
        "visible_without_attack":  visible_without_attack,
        "visible_without_d3fend":  visible_without_d3fend,
        "can_add_usecases":        can_add_usecases(request.user, _roles=roles),
        "can_manage_usecases":     any(uc.can_manage_by_user for uc in qs),
        "can_delete_usecases":     any(uc.can_delete_by_user for uc in qs),
    }
    return render(request, "usecases/usecase_list.html", context)


@login_required
def export_usecases_csv(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    qs, _ = _get_filtered_usecases(request, with_prefetch=True)
    qs = qs.order_by("name")

    response = HttpResponse(content_type="text/csv; charset=utf-8-sig")
    response["Content-Disposition"] = 'attachment; filename="usecases_export.csv"'
    writer = csv.writer(response)
    writer.writerow([
        "Identificador", "Nombre", "Dispositivo", "Fuentes", "Responsable desarrollo", "Estado", "Severidad",
        "Ultimo control", "Proximo control", "Habilitado", "Motivo deshabilitacion", "ATT&CK", "D3FEND",
    ])
    for uc in qs:
        writer.writerow([
            uc.display_code, uc.name, uc.device, _serialize_sources(uc), uc.owner_name, uc.status, uc.severity,
            uc.last_validation_date or "", uc.next_review_date or "",
            "Si" if uc.is_enabled else "No", uc.disabled_reason or "",
            _serialize_mitre(uc), _serialize_d3fend(uc),
        ])
    return response


def _xlsx_response(workbook, filename: str):
    buffer = BytesIO()
    workbook.save(buffer)
    response = HttpResponse(
        buffer.getvalue(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def _append_usecase_excel_row(ws, usecase):
    ws.append([
        usecase.display_code,
        usecase.group_name,
        usecase.device,
        usecase.case_type,
        usecase.objective,
        usecase.blocking_type,
        usecase.name,
        usecase.owner_name,
        usecase.monitoring,
        usecase.status,
        usecase.created_or_adjusted_at,
        usecase.production_date,
        _serialize_mitre(usecase),
        usecase.severity,
        usecase.escalation,
        usecase.sent_to_ho,
        usecase.ho_flag,
        _serialize_sources(usecase),
        usecase.last_validation_date,
    ])


def _usecase_excel_headers():
    return [
        "IDENTIFICADOR",
        "GRUPO",
        "DISPOSITIVO",
        "TIPO",
        "OBJETIVO2",
        "Tipo_bloqueo",
        "NOMBRE NETWITNESS",
        "RESPONSABLE",
        "Monitoreo",
        "status2",
        "Fecha alta/ajuste",
        "Fecha puesta en producción",
        "MITRE ATT&CK",
        "Severidad",
        "Escalamiento",
        "ENVIO.HO",
        "HO",
        "FUENTES",
        "Fecha última validación",
    ]


@login_required
def export_usecases_xlsx(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    qs, _ = _get_filtered_usecases(request, with_prefetch=True)
    wb = Workbook()
    ws = wb.active
    ws.title = "Casos de uso"
    ws.append(_usecase_excel_headers())
    for usecase in qs.order_by("name"):
        _append_usecase_excel_row(ws, usecase)
    return _xlsx_response(wb, "usecases_export.xlsx")


@login_required
def download_usecase_import_template(request):
    if not can_add_usecases(request.user):
        return HttpResponseForbidden("No tenes permisos para importar casos de uso.")

    wb = Workbook()
    ws = wb.active
    ws.title = "Casos de uso"
    ws.append(_usecase_excel_headers())
    ws.append([
        "Ejemplo - PowerShell sospechoso",
        "SOC",
        "SIEM",
        "Correlation",
        "Detectar ejecucion sospechosa",
        "Manual",
        "Ejemplo - PowerShell sospechoso",
        "analyst",
        "24x7",
        UseCase.STATUS_PRODUCTION,
        date.today(),
        date.today(),
        "T1059 - Command and Scripting Interpreter",
        "High",
        "SOC",
        "No",
        "No",
        "DEMO-EDR - Demo EDR; DEMO-SIEM - Demo SIEM",
        date.today(),
    ])
    return _xlsx_response(wb, "plantilla_casos_uso.xlsx")


@login_required
def import_usecases_excel(request):
    if not can_add_usecases(request.user):
        return HttpResponseForbidden("No tenes permisos para importar casos de uso.")

    if request.method == "POST":
        uploaded_file = request.FILES.get("excel_file")
        allow_update = request.POST.get("update_existing") == "on"
        if not uploaded_file:
            messages.error(request, "Selecciona un archivo Excel para importar.")
            return redirect("import_usecases_excel")

        suffix = Path(uploaded_file.name).suffix.lower()
        if suffix != ".xlsx":
            messages.error(request, "El archivo debe ser .xlsx. No se aceptan .xlsm ni archivos con macros.")
            return redirect("import_usecases_excel")

        temp_path = None
        output = StringIO()
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                temp_path = temp_file.name
                for chunk in uploaded_file.chunks():
                    temp_file.write(chunk)
            call_command("import_usecases", temp_path, update=allow_update, stdout=output)
        except Exception as exc:
            messages.error(request, f"No se pudo importar el Excel: {exc}")
        else:
            messages.success(request, "Importacion finalizada. Revisa el resumen debajo.")
            request.session["last_usecase_import_output"] = output.getvalue()
            return redirect("import_usecases_excel")
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink(missing_ok=True)
                except OSError:
                    pass

    import_output = request.session.pop("last_usecase_import_output", "")
    return render(request, "usecases/import_usecases_excel.html", {
        "import_output": import_output,
    })


@login_required
def usecase_inventory_history(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    return redirect("/audit/?area=inventory")


@login_required
def usecase_create(request):
    if not can_add_usecases(request.user):
        return HttpResponseForbidden("No tenes permisos para crear casos de uso.")

    if request.method == "POST":
        form = UseCaseForm(request.POST)
        condition_formset = UseCaseRuleConditionFormSet(request.POST, instance=form.instance, prefix="conditions")
        if form.is_valid() and condition_formset.is_valid():
            usecase = form.save(commit=False)
            usecase.created_by = request.user
            usecase.updated_by = request.user
            if not usecase.owner_name:
                usecase.owner_name = request.user.get_full_name() or request.user.username
            usecase.save()
            form.save_m2m()
            condition_formset.instance = usecase
            condition_formset.save()
            _sync_usecase_sources(usecase, form.cleaned_data.get("event_sources", []), request.user)
            sync_inventory_rule_backup(usecase, request.user)
            usecase.sync_d3fends_from_attacks()
            messages.success(request, "Caso de uso creado correctamente.")
            return redirect("usecase_detail", pk=usecase.pk)
    else:
        form = UseCaseForm()
        condition_formset = UseCaseRuleConditionFormSet(prefix="conditions")

    return render(request, "usecases/usecase_form.html", {
        "form": form,
        "condition_formset": condition_formset,
        "title": "Crear caso",
    })


@login_required
def usecase_edit(request, pk):
    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends", "d3fend_exclusions", "source_links__source"), pk=pk,
    )
    if not can_manage_usecases(request.user, usecase):
        return HttpResponseForbidden("Solo podes editar casos de uso propios.")

    old_data = _snapshot_usecase(usecase)

    if request.method == "POST":
        form = UseCaseForm(request.POST, instance=usecase)
        condition_formset = UseCaseRuleConditionFormSet(request.POST, instance=usecase, prefix="conditions")
        if form.is_valid() and condition_formset.is_valid():
            updated = form.save(commit=False)
            # Preserve lifecycle dates - managed only by the lifecycle review system.
            updated.last_review_date = usecase.last_review_date
            updated.next_review_date = usecase.next_review_date
            updated.updated_by = request.user
            updated.save()
            form.save_m2m()
            condition_formset.instance = updated
            condition_formset.save()
            _sync_usecase_sources(updated, form.cleaned_data.get("event_sources", []), request.user)
            sync_inventory_rule_backup(updated, request.user)
            updated.sync_d3fends_from_attacks()
            new_data = _snapshot_usecase(updated)
            UseCaseChangeLog.create_diff(updated, old_data, new_data, request.user)
            messages.success(request, "Caso de uso actualizado correctamente.")
            return redirect("usecase_detail", pk=updated.pk)
    else:
        form = UseCaseForm(instance=usecase)
        condition_formset = UseCaseRuleConditionFormSet(instance=usecase, prefix="conditions")

    usecase.form_inferred_d3fends = list(usecase.base_inferred_d3fends_queryset())
    return render(
        request, "usecases/usecase_form.html",
        {
            "form": form,
            "condition_formset": condition_formset,
            "title": "Editar caso de uso",
            "usecase": usecase,
        },
    )


@login_required
def usecase_detail(request, pk):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends", "d3fend_exclusions", "source_links__source", "rule_conditions"), pk=pk,
    )

    usecase.inferred_d3fends = list(usecase.inferred_d3fends_queryset())
    current_backup = UseCaseTechnicalBackup.current_for_usecase(usecase)

    return render(
        request, "usecases/usecase_detail.html",
        {
            "usecase":              usecase,
            "current_backup": current_backup,
            "can_manage_usecases":    can_manage_usecases(request.user, usecase),
            "can_delete_usecases":  can_delete_usecases(request.user, usecase),
        },
    )


@login_required
def usecase_quick_update(request, pk):
    if request.method != "POST":
        return redirect("usecase_list")

    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends", "d3fend_exclusions"), pk=pk,
    )
    if not can_manage_usecases(request.user, usecase):
        return HttpResponseForbidden("Solo podes actualizar casos de uso propios.")

    old_data = _snapshot_usecase(usecase)

            # Preserve lifecycle dates - managed only by the lifecycle review system.
    _saved_last_review = usecase.last_review_date
    _saved_next_review = usecase.next_review_date

    usecase.owner_name        = request.POST.get("owner_name", "").strip()
    if "status" in request.POST:
        usecase.status = request.POST.get("status", "").strip()
    usecase.severity          = request.POST.get("severity", "").strip()
    usecase.validation_status = request.POST.get("validation_status", "").strip()
    usecase.validation_result = request.POST.get("validation_result", "").strip()
    usecase.last_validation_date = _parse_date_field(
        request.POST.get("last_validation_date", "").strip()
    )
    usecase.is_enabled = request.POST.get("is_enabled") == "on"
    if "disabled_reason" in request.POST:
        usecase.disabled_reason = request.POST.get("disabled_reason", "").strip()
    usecase.last_review_date = _saved_last_review
    usecase.next_review_date = _saved_next_review

    posted_mitre_ids = _parse_csv_ids(request.POST.get("mitre_attack_ids", ""))
    errors = _usecase_business_rule_errors(usecase, mitre_ids=posted_mitre_ids)
    if errors:
        for error in errors:
            messages.error(request, error)
        return redirect("usecase_list")

    usecase.updated_by = request.user
    usecase.save()

    usecase.mitre_attacks.set(
        MitreAttack.objects.filter(id__in=posted_mitre_ids)
    )
    usecase.sync_d3fends_from_attacks()

    new_data = _snapshot_usecase(usecase)
    UseCaseChangeLog.create_diff(usecase, old_data, new_data, request.user)
    messages.success(request, f"Se actualizo '{usecase.name}'.")
    return redirect("usecase_list")


@login_required
def usecase_bulk_update(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    if request.method != "POST":
        return redirect("usecase_list")

    return_qs = request.POST.get("return_qs", "").strip()
    if not parse_posted_usecase_ids(request.POST):
        messages.info(request, "No se detectaron cambios para guardar.")
        return _redirect_usecase_list_with_query(return_qs)

    result = update_usecases_bulk(
        user=request.user,
        post_data=request.POST,
        parse_date=_parse_date_field,
        validate_usecase=_usecase_business_rule_errors,
        snapshot_usecase=_snapshot_usecase,
    )

    for error in result.errors:
        messages.error(request, error)

    if result.updated_count:
        messages.success(request, f"Se actualizaron {result.updated_count} caso(s).")
        return _redirect_usecase_list_with_query(return_qs)

    messages.info(request, "No se detectaron cambios para guardar.")
    return _redirect_usecase_list_with_query(return_qs)


@login_required
def usecase_delete(request, pk):
    if request.method != "POST":
        return redirect("usecase_detail", pk=pk)

    usecase = get_object_or_404(UseCase, pk=pk)
    if not can_delete_usecases(request.user, usecase):
        return HttpResponseForbidden("Solo podes eliminar casos de uso propios si tenes permiso de borrado.")

    name = usecase.name
    usecase.delete()
    messages.success(request, f"Caso de uso '{name}' eliminado.")
    return redirect("usecase_list")
