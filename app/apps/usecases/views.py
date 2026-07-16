from datetime import date, timedelta, datetime
import csv
from io import BytesIO, StringIO
import re
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
from .management.commands.import_usecases import (
    DATE_FIELDS,
    extract_attack_ids,
    find_existing_usecase,
    normalize_blocking_type,
    normalize_escalation,
    normalize_key,
    normalize_severity,
    normalize_status,
    normalize_text,
    normalize_yes_no,
    parse_date,
    resolve_attack_objects,
)
from apps.mitre.models import D3Fend, MitreAttack
from apps.sources.matching import sync_usecase_sources
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
D3FEND_ID_RE = re.compile(r"\bD3-[A-Z0-9]+\b", re.IGNORECASE)


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


def _serialize_d3fend_exclusions(usecase):
    return "; ".join(
        f"{d3fend.code} - {d3fend.name}"
        for d3fend in usecase.d3fend_exclusions.all().order_by("code", "name")
    )


def _serialize_inferred_d3fends(usecase):
    queryset = (
        usecase.d3fends.all()
        if hasattr(usecase, "_prefetched_objects_cache") and "d3fends" in usecase._prefetched_objects_cache
        else usecase.inferred_d3fends_queryset()
    )
    return "; ".join(
        f"{d3fend.code} - {d3fend.name}"
        for d3fend in sorted(queryset, key=lambda item: (item.code, item.name))
    )


def _extract_d3fend_codes(value):
    if not value:
        return []
    return sorted({item.upper() for item in D3FEND_ID_RE.findall(str(value))})


def _resolve_d3fend_objects(codes):
    if not codes:
        return [], []
    d3fends = list(D3Fend.objects.filter(code__in=codes, is_enabled=True).order_by("code"))
    found = {item.code.upper() for item in d3fends}
    missing = [code for code in codes if code.upper() not in found]
    return d3fends, missing


def _format_import_lines(lines):
    return "\n".join(lines).strip()


def _full_csv_headers():
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
        "Fecha puesta en produccion",
        "MITRE ATT&CK",
        "D3FEND_EXCLUIDO",
        "D3FEND_INFERIDO",
        "Severidad",
        "Escalamiento",
        "ENVIO.HO",
        "FUENTES",
        "Fecha ultima validacion",
        "Habilitado",
        "Motivo deshabilitacion",
        "Comentarios",
        "Regla completa",
        "Descripcion funcional",
    ]


CSV_FULL_FIELD_ALIASES = {
    "identificador": "case_code",
    "codigo": "case_code",
    "codigocaso": "case_code",
    "grupo": "group_name",
    "dispositivo": "device",
    "tipo": "case_type",
    "objetivo": "objective",
    "objetivo2": "objective",
    "tipobloqueo": "blocking_type",
    "nombrenetwitness": "name",
    "nombre": "name",
    "casodeuso": "name",
    "responsable": "owner_name",
    "monitoreo": "monitoring",
    "estado": "status",
    "status": "status",
    "status2": "status",
    "fechaaltajuste": "created_or_adjusted_at",
    "fechapuestaenproduccion": "production_date",
    "fechaproduccion": "production_date",
    "mitre": "mitre_attack_rel",
    "mitreattack": "mitre_attack_rel",
    "mitreattck": "mitre_attack_rel",
    "mitreattckrelacionado": "mitre_attack_rel",
    "mitreattackrelacionado": "mitre_attack_rel",
    "mitretecnicas": "mitre_attack_rel",
    "d3fendexcluido": "d3fend_exclusions_raw",
    "d3fendexclusiones": "d3fend_exclusions_raw",
    "d3fendexclusions": "d3fend_exclusions_raw",
    "d3fendinferido": "d3fend_inferred_readonly",
    "d3fend": "d3fend_inferred_readonly",
    "severidad": "severity",
    "severity": "severity",
    "escalamiento": "escalation",
    "envioho": "sent_to_ho",
    "fuente": "event_sources_raw",
    "fuentes": "event_sources_raw",
    "fuenteseventos": "event_sources_raw",
    "fechaultimavalidacion": "last_validation_date",
    "ultimavalidacion": "last_validation_date",
    "habilitado": "is_enabled",
    "enabled": "is_enabled",
    "motivodeshabilitacion": "disabled_reason",
    "motivobaja": "disabled_reason",
    "comentarios": "comments",
    "comments": "comments",
    "reglacompleta": "full_rule_text",
    "fullrule": "full_rule_text",
    "descripcionfuncional": "functional_description",
    "description": "functional_description",
}


def _append_usecase_full_csv_row(writer, usecase):
    writer.writerow([
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
        usecase.created_or_adjusted_at or "",
        usecase.production_date or "",
        _serialize_mitre(usecase),
        _serialize_d3fend_exclusions(usecase),
        _serialize_inferred_d3fends(usecase),
        usecase.severity,
        usecase.escalation,
        usecase.sent_to_ho,
        _serialize_sources(usecase),
        usecase.last_validation_date or "",
        "Si" if usecase.is_enabled else "No",
        usecase.disabled_reason,
        usecase.comments,
        usecase.full_rule_text,
        usecase.functional_description,
    ])


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


@login_required
def export_usecases_full_csv(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    qs, _ = _get_filtered_usecases(request, with_prefetch=True)
    qs = qs.order_by("name")

    response = HttpResponse(content_type="text/csv; charset=utf-8-sig")
    response["Content-Disposition"] = 'attachment; filename="inventario_casos_uso_completo.csv"'
    writer = csv.writer(response)
    writer.writerow(_full_csv_headers())
    for usecase in qs:
        _append_usecase_full_csv_row(writer, usecase)
    return response


def _decode_csv_upload(uploaded_file):
    raw_content = uploaded_file.read()
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw_content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_content.decode("utf-8", errors="replace")


def _parse_csv_bool(value, default=True):
    key = normalize_key(value)
    if not key:
        return default
    if key in {"1", "si", "s", "yes", "y", "true", "x", "habilitado", "activo", "activa"}:
        return True
    if key in {"0", "no", "n", "false", "deshabilitado", "inhabilitado", "inactivo", "inactiva"}:
        return False
    return default


def _map_full_csv_row(row):
    payload = {}
    attack_raw = ""
    d3fend_exclusions_raw = ""
    sources_raw = None

    for raw_header, raw_value in row.items():
        field_name = CSV_FULL_FIELD_ALIASES.get(normalize_key(raw_header))
        if not field_name:
            continue

        value = normalize_text(raw_value)
        if field_name == "mitre_attack_rel":
            attack_raw = value
            continue
        if field_name == "d3fend_exclusions_raw":
            d3fend_exclusions_raw = value
            continue
        if field_name == "d3fend_inferred_readonly":
            continue
        if field_name == "event_sources_raw":
            sources_raw = value
            continue
        if field_name in DATE_FIELDS:
            payload[field_name] = parse_date(raw_value)
            continue
        if field_name == "is_enabled":
            payload[field_name] = _parse_csv_bool(raw_value)
            continue
        payload[field_name] = value

    if "status" in payload:
        payload["status"] = normalize_status(payload.get("status", ""))
    if "blocking_type" in payload:
        payload["blocking_type"] = normalize_blocking_type(payload.get("blocking_type", ""))
    if "severity" in payload:
        payload["severity"] = normalize_severity(payload.get("severity", ""))
    if "escalation" in payload:
        payload["escalation"] = normalize_escalation(payload.get("escalation", ""))
    if "sent_to_ho" in payload:
        payload["sent_to_ho"] = normalize_yes_no(payload.get("sent_to_ho", ""))

    return payload, attack_raw, d3fend_exclusions_raw, sources_raw


@login_required
def import_usecases_csv(request):
    if not can_add_usecases(request.user):
        return HttpResponseForbidden("No tenes permisos para importar casos de uso.")

    if request.method != "POST":
        return redirect("import_usecases_excel")

    uploaded_file = request.FILES.get("csv_file")
    allow_update = request.POST.get("update_existing") == "on"
    if not uploaded_file:
        messages.error(request, "Selecciona un archivo CSV para importar.")
        return redirect("import_usecases_excel")

    if Path(uploaded_file.name).suffix.lower() != ".csv":
        messages.error(request, "El archivo debe ser .csv.")
        return redirect("import_usecases_excel")

    output_lines = []
    created_count = 0
    updated_count = 0
    skipped_count = 0
    error_count = 0
    warning_count = 0
    attack_assigned_count = 0
    d3fend_exclusion_count = 0
    d3fend_no_mapping_count = 0
    d3fend_all_excluded_count = 0
    sources_created_count = 0

    try:
        content = _decode_csv_upload(uploaded_file)
        reader = csv.DictReader(StringIO(content))
        if not reader.fieldnames:
            raise ValueError("El CSV no tiene encabezados.")

        for row_num, row in enumerate(reader, start=2):
            try:
                payload, attack_raw, d3fend_exclusions_raw, sources_raw = _map_full_csv_row(row)
                name = payload.get("name", "").strip()
                if not name:
                    skipped_count += 1
                    output_lines.append(f"Fila {row_num}: omitida por no tener NOMBRE NETWITNESS.")
                    continue
                if not payload.get("case_code"):
                    payload["case_code"] = name

                attack_ids = extract_attack_ids(attack_raw)
                attack_objects, missing_attack_ids = resolve_attack_objects(attack_ids)
                if missing_attack_ids:
                    warning_count += 1
                    output_lines.append(
                        f"Fila {row_num}: ATT&CK no encontrados en el catalogo -> {', '.join(missing_attack_ids)}."
                    )

                d3fend_codes = _extract_d3fend_codes(d3fend_exclusions_raw)
                d3fend_exclusions, missing_d3fend_codes = _resolve_d3fend_objects(d3fend_codes)
                if missing_d3fend_codes:
                    warning_count += 1
                    output_lines.append(
                        f"Fila {row_num}: D3FEND excluidos no encontrados en el catalogo -> "
                        + ", ".join(missing_d3fend_codes)
                    )

                instance = find_existing_usecase(name, payload.get("case_code", ""))
                if instance and not allow_update:
                    skipped_count += 1
                    output_lines.append(
                        f"Fila {row_num}: ya existe '{instance.name}', omitido. "
                        "Activa 'Actualizar existentes' para pisar los datos."
                    )
                    continue

                if instance:
                    for field, value in payload.items():
                        setattr(instance, field, value)
                    instance.updated_by = request.user
                    instance.save()
                    action = "actualizado"
                    updated_count += 1
                else:
                    payload.setdefault("created_by", request.user)
                    payload.setdefault("updated_by", request.user)
                    instance = UseCase.objects.create(**payload)
                    action = "creado"
                    created_count += 1

                instance.mitre_attacks.set(attack_objects)
                attack_assigned_count += len(attack_objects)
                instance.d3fend_exclusions.set(d3fend_exclusions)
                d3fend_exclusion_count += len(d3fend_exclusions)
                instance.sync_d3fends_from_attacks()
                if attack_objects and not instance.d3fends.exists():
                    if instance.base_inferred_d3fends_queryset().exists():
                        d3fend_all_excluded_count += 1
                    else:
                        d3fend_no_mapping_count += 1

                if sources_raw == "":
                    instance.source_links.all().delete()
                    source_result = {"created": 0, "unresolved": []}
                else:
                    source_result = sync_usecase_sources(
                        instance,
                        sources_raw,
                        create_missing=True,
                        defaults={"description": "Creada automaticamente desde importacion CSV de inventario."},
                    )
                    sources_created_count += source_result["created"]
                    if source_result["unresolved"]:
                        warning_count += 1
                        output_lines.append(
                            f"Fila {row_num}: fuentes no resueltas -> {', '.join(source_result['unresolved'])}."
                        )

                sync_inventory_rule_backup(instance, request.user)
                output_lines.append(f"Fila {row_num}: {action} '{name}'.")
            except Exception as exc:
                error_count += 1
                output_lines.append(f"Fila {row_num}: error -> {exc}")

    except Exception as exc:
        messages.error(request, f"No se pudo importar el CSV: {exc}")
        return redirect("import_usecases_excel")

    output_lines.extend([
        "",
        "Importacion CSV finalizada",
        f"Creados: {created_count}",
        f"Actualizados: {updated_count}",
        f"Omitidos: {skipped_count}",
        f"Errores: {error_count}",
        f"Advertencias: {warning_count}",
        f"MITRE asociados: {attack_assigned_count}",
        f"D3FEND excluidos: {d3fend_exclusion_count}",
        f"Casos sin mapping D3FEND oficial: {d3fend_no_mapping_count}",
        f"Casos con D3FEND oficial totalmente excluido: {d3fend_all_excluded_count}",
        f"Fuentes creadas: {sources_created_count}",
    ])
    request.session["last_usecase_import_output"] = _format_import_lines(output_lines)
    if error_count:
        messages.warning(request, "Importacion CSV finalizada con errores. Revisa el resumen debajo.")
    else:
        messages.success(request, "Importacion CSV finalizada. Revisa el resumen debajo.")
    return redirect("import_usecases_excel")


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
