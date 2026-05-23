from collections import Counter
from datetime import date, timedelta, datetime
import csv
from io import BytesIO

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse, JsonResponse, HttpResponseForbidden, QueryDict
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from .attack_matrix import build_attack_matrix_context
from .d3fend_matrix import build_d3fend_matrix_context
from .dashboard import build_dashboard_context
from .forms import UseCaseForm
from .coverage_overrides import get_override_map, item_matches_query, resolve_status, split_values
from .lifecycle import current_lifecycle_window
from .models import CoverageOverride, D3Fend, LifecycleReview, MitreAttack, UseCase, UseCaseChangeLog
from .permissions import (
    can_access_usecases,
    can_add_usecases,
    can_assign_lifecycle_owner,
    can_delete_usecases,
    can_finish_lifecycle_review,
    can_manage_usecases,
    is_lifecycle_admin as user_is_lifecycle_admin,
    resolve_user_roles,
)
from .reports import build_dashboard_pdf, get_active_dashboard_report_settings

_FORBIDDEN_MSG = "No tenés permisos para acceder a esta sección."
PRODUCTION_STATUS = UseCase.STATUS_PRODUCTION


# ── Helpers ──────────────────────────────────────────────────────────────────


def _get_filtered_usecases(request, *, with_prefetch: bool = True, ignore_quick: bool = False):
    # El inventario operativo y los links del dashboard trabajan solo sobre casos
    # en Producción. Los estados Draft/Test/Desarrollo/Baja no participan en
    # cobertura ni se pueden consultar desde estos filtros del front.
    qs = UseCase.objects.filter(status__iexact=PRODUCTION_STATUS)

    if with_prefetch:
        qs = qs.prefetch_related("mitre_attacks", "d3fends")

    q              = request.GET.get("q", "").strip()
    status         = PRODUCTION_STATUS
    device         = request.GET.get("device", "").strip()
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
        qs = qs.filter(name__icontains=q)
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
        "q": q, "status": status, "device": device, "severity": severity,
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
    query.pop("status", None)

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
    inferred = getattr(usecase, "inferred_d3fends", None)
    if inferred is None:
        inferred = usecase.inferred_d3fends_queryset()

    return ", ".join(
        f"{item.code} - {item.name}" if item.name else str(item.code)
        for item in inferred
    )



def _serialize_user(user) -> str:
    if not user:
        return ""

    full_name = ""
    if hasattr(user, "get_full_name"):
        full_name = (user.get_full_name() or "").strip()

    username = (getattr(user, "username", "") or "").strip()

    if full_name and username:
        return f"{full_name} ({username})"
    return full_name or username or str(user)



def _snapshot_usecase(usecase) -> dict:
    return {
        "name":                    usecase.name,
        "group_name":              usecase.group_name,
        "device":                  usecase.device,
        "case_type":               usecase.case_type,
        "objective":               usecase.objective,
        "blocking_type":           usecase.blocking_type,
        "owner_name":              usecase.owner_name,
        "lifecycle_control_owner": _serialize_user(usecase.lifecycle_control_owner),
        "monitoring":              usecase.monitoring,
        "status":                  usecase.status,
        "created_or_adjusted_at":  usecase.created_or_adjusted_at,
        "production_date":         usecase.production_date,
        "mitre_attacks":           _serialize_mitre(usecase),
        "d3fends":                 _serialize_d3fend(usecase),
        "severity":                usecase.severity,
        "escalation":              usecase.escalation,
        "sent_to_ho":              usecase.sent_to_ho,
        "ho_flag":                 usecase.ho_flag,
        "last_validation_date":    usecase.last_validation_date,
        "validation_status":       usecase.validation_status,
        "validation_result":       usecase.validation_result,
        "is_enabled":              usecase.is_enabled,
        "disabled_reason":         usecase.disabled_reason,
        "last_review_date":        usecase.last_review_date,
        "next_review_date":        usecase.next_review_date,
        "comments":                usecase.comments,
    }


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



def _coverage_status_label(status: str) -> str:
    return dict(CoverageOverride.STATUS_CHOICES).get(status, status)


def _coverage_admin_status_options():
    return CoverageOverride.STATUS_CHOICES


def _coverage_object_type_label(object_type: str) -> str:
    return dict(CoverageOverride.OBJECT_TYPE_CHOICES).get(object_type, object_type)


def _build_attack_tactic_rows(q: str, overrides: dict) -> list[dict]:
    tactic_map: dict[str, dict] = {}
    qs = MitreAttack.objects.all().only("external_id", "name", "tactic", "is_enabled").order_by("external_id", "name")
    for attack in qs:
        attack_tactics = split_values(attack.tactic) or ["Sin táctica"]
        for tactic in attack_tactics:
            data = tactic_map.setdefault(
                tactic,
                {
                    "techniques": 0,
                    "enabled": 0,
                    "fulfilled": 0,
                    "disabled": 0,
                    "search_values": {tactic},
                },
            )
            data["search_values"].update([attack.external_id, attack.name, attack.tactic])
            technique_status = resolve_status(
                overrides,
                framework=CoverageOverride.FRAMEWORK_ATTACK,
                object_type=CoverageOverride.OBJECT_TECHNIQUE,
                object_key=attack.external_id,
                default_enabled=attack.is_enabled,
            )
            data["techniques"] += 1
            if technique_status.status == CoverageOverride.STATUS_FULFILLED:
                data["fulfilled"] += 1
            elif technique_status.status == CoverageOverride.STATUS_DISABLED:
                data["disabled"] += 1
            else:
                data["enabled"] += 1

    rows = []
    for tactic, data in tactic_map.items():
        # In the tactic scope the visible row is the tactic, but the user will
        # naturally search by child technique ID/name as well. Include those
        # child values so the search does not look broken from the default tab.
        if not item_matches_query(data["search_values"], q):
            continue
        status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_ATTACK,
            object_type=CoverageOverride.OBJECT_TACTIC,
            object_key=tactic,
            default_enabled=True,
        )
        rows.append({
            "framework": CoverageOverride.FRAMEWORK_ATTACK,
            "object_type": CoverageOverride.OBJECT_TACTIC,
            "object_type_label": "Táctica",
            "object_key": tactic,
            "object_name": tactic,
            "title": tactic,
            "subtitle": f"{data['techniques']} técnicas/subtécnicas · {data['fulfilled']} cumplidas · {data['disabled']} deshabilitadas",
            "status": status.status,
            "status_label": status.label,
            "status_class": status.css_class,
            "reason": status.reason,
            "default_enabled": True,
            "source": status.source,
        })
    return sorted(rows, key=lambda row: row["title"].lower())


def _build_attack_technique_rows(q: str, overrides: dict) -> list[dict]:
    rows = []
    qs = MitreAttack.objects.all().order_by("external_id", "name")
    for attack in qs:
        if not item_matches_query([attack.external_id, attack.name, attack.tactic], q):
            continue
        status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_ATTACK,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=attack.external_id,
            default_enabled=attack.is_enabled,
        )
        rows.append({
            "framework": CoverageOverride.FRAMEWORK_ATTACK,
            "object_type": CoverageOverride.OBJECT_TECHNIQUE,
            "object_type_label": "Técnica",
            "object_key": attack.external_id,
            "object_name": attack.name,
            "title": f"{attack.external_id} · {attack.name or 'Sin nombre'}",
            "subtitle": attack.tactic or "Sin táctica",
            "status": status.status,
            "status_label": status.label,
            "status_class": status.css_class,
            "reason": status.reason,
            "default_enabled": attack.is_enabled,
            "source": status.source,
        })
    return rows


def _build_d3fend_category_rows(q: str, overrides: dict) -> list[dict]:
    category_map: dict[str, dict] = {}
    qs = D3Fend.objects.all().only("code", "name", "category", "is_enabled").order_by("category", "code")
    for d3fend in qs:
        category = d3fend.category or "Sin categoría"
        data = category_map.setdefault(
            category,
            {
                "techniques": 0,
                "enabled": 0,
                "fulfilled": 0,
                "disabled": 0,
                "search_values": {category},
            },
        )
        data["search_values"].update([d3fend.code, d3fend.name, d3fend.category])
        technique_status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_D3FEND,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=d3fend.code,
            default_enabled=d3fend.is_enabled,
        )
        data["techniques"] += 1
        if technique_status.status == CoverageOverride.STATUS_FULFILLED:
            data["fulfilled"] += 1
        elif technique_status.status == CoverageOverride.STATUS_DISABLED:
            data["disabled"] += 1
        else:
            data["enabled"] += 1

    rows = []
    for category, data in category_map.items():
        # Same UX rule as ATT&CK tactics: in the category scope, searching by a
        # child D3FEND code/name should still return the parent category.
        if not item_matches_query(data["search_values"], q):
            continue
        status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_D3FEND,
            object_type=CoverageOverride.OBJECT_CATEGORY,
            object_key=category,
            default_enabled=True,
        )
        rows.append({
            "framework": CoverageOverride.FRAMEWORK_D3FEND,
            "object_type": CoverageOverride.OBJECT_CATEGORY,
            "object_type_label": "Categoría",
            "object_key": category,
            "object_name": category,
            "title": category,
            "subtitle": f"{data['techniques']} técnicas · {data['fulfilled']} cumplidas · {data['disabled']} deshabilitadas",
            "status": status.status,
            "status_label": status.label,
            "status_class": status.css_class,
            "reason": status.reason,
            "default_enabled": True,
            "source": status.source,
        })
    return sorted(rows, key=lambda row: row["title"].lower())


def _build_d3fend_technique_rows(q: str, overrides: dict) -> list[dict]:
    rows = []
    qs = D3Fend.objects.all().order_by("code", "name")
    for d3fend in qs:
        if not item_matches_query([d3fend.code, d3fend.name, d3fend.category], q):
            continue
        status = resolve_status(
            overrides,
            framework=CoverageOverride.FRAMEWORK_D3FEND,
            object_type=CoverageOverride.OBJECT_TECHNIQUE,
            object_key=d3fend.code,
            default_enabled=d3fend.is_enabled,
        )
        rows.append({
            "framework": CoverageOverride.FRAMEWORK_D3FEND,
            "object_type": CoverageOverride.OBJECT_TECHNIQUE,
            "object_type_label": "Técnica",
            "object_key": d3fend.code,
            "object_name": d3fend.name,
            "title": f"{d3fend.code} · {d3fend.name or 'Sin nombre'}",
            "subtitle": d3fend.category or "Sin categoría",
            "status": status.status,
            "status_label": status.label,
            "status_class": status.css_class,
            "reason": status.reason,
            "default_enabled": d3fend.is_enabled,
            "source": status.source,
        })
    return rows


# ── Views ─────────────────────────────────────────────────────────────────────

@login_required
def dashboard_view(request):
    return render(request, "dashboard.html", build_dashboard_context(request))


@login_required
def dashboard_pdf_export(request):
    # FIX: removed duplicate @login_required; added can_access_usecases guard
    # so ReadOnly users cannot export the full PDF.
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    context        = build_dashboard_context(request)
    report_settings = get_active_dashboard_report_settings()
    buffer         = BytesIO()
    build_dashboard_pdf(buffer, context, report_settings, request.user)
    response = HttpResponse(buffer.getvalue(), content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="dashboard-soc-{date.today():%Y%m%d}.pdf"'
    return response


@login_required
def attack_matrix_view(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    return render(request, "usecases/attack_matrix.html", build_attack_matrix_context(request))


@login_required
def d3fend_matrix_view(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    return render(request, "usecases/d3fend_matrix.html", build_d3fend_matrix_context(request))


@login_required
def coverage_admin_view(request):
    if not can_manage_usecases(request.user, None):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    tab = request.GET.get("tab", CoverageOverride.FRAMEWORK_ATTACK).strip().upper()
    if tab not in {CoverageOverride.FRAMEWORK_ATTACK, CoverageOverride.FRAMEWORK_D3FEND}:
        tab = CoverageOverride.FRAMEWORK_ATTACK

    if tab == CoverageOverride.FRAMEWORK_ATTACK:
        scope = request.GET.get("scope", CoverageOverride.OBJECT_TACTIC).strip().lower()
        allowed_scopes = {CoverageOverride.OBJECT_TACTIC, CoverageOverride.OBJECT_TECHNIQUE}
    else:
        scope = request.GET.get("scope", CoverageOverride.OBJECT_CATEGORY).strip().lower()
        allowed_scopes = {CoverageOverride.OBJECT_CATEGORY, CoverageOverride.OBJECT_TECHNIQUE}
    if scope not in allowed_scopes:
        scope = CoverageOverride.OBJECT_TACTIC if tab == CoverageOverride.FRAMEWORK_ATTACK else CoverageOverride.OBJECT_CATEGORY

    q = request.GET.get("q", "").strip()
    status_filter = request.GET.get("status", "").strip()
    if status_filter not in {"", CoverageOverride.STATUS_ENABLED, CoverageOverride.STATUS_FULFILLED, CoverageOverride.STATUS_DISABLED}:
        status_filter = ""

    overrides = get_override_map(tab)
    if tab == CoverageOverride.FRAMEWORK_ATTACK and scope == CoverageOverride.OBJECT_TACTIC:
        rows = _build_attack_tactic_rows(q, overrides)
    elif tab == CoverageOverride.FRAMEWORK_ATTACK:
        rows = _build_attack_technique_rows(q, overrides)
    elif scope == CoverageOverride.OBJECT_CATEGORY:
        rows = _build_d3fend_category_rows(q, overrides)
    else:
        rows = _build_d3fend_technique_rows(q, overrides)

    counters = Counter(row["status"] for row in rows)
    if status_filter:
        rows = [row for row in rows if row["status"] == status_filter]

    paginator = Paginator(rows, 25)
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "usecases/coverage_admin.html", {
        "rows": page_obj.object_list,
        "page_obj": page_obj,
        "paginator": paginator,
        "tab": tab,
        "scope": scope,
        "q": q,
        "status_filter": status_filter,
        "status_options": _coverage_admin_status_options(),
        "counters": counters,
        "counter_enabled": counters.get(CoverageOverride.STATUS_ENABLED, 0),
        "counter_fulfilled": counters.get(CoverageOverride.STATUS_FULFILLED, 0),
        "counter_disabled": counters.get(CoverageOverride.STATUS_DISABLED, 0),
        "total_rows": len(rows),
        "attack_framework": CoverageOverride.FRAMEWORK_ATTACK,
        "d3fend_framework": CoverageOverride.FRAMEWORK_D3FEND,
        "object_tactic": CoverageOverride.OBJECT_TACTIC,
        "object_technique": CoverageOverride.OBJECT_TECHNIQUE,
        "object_category": CoverageOverride.OBJECT_CATEGORY,
    })


@login_required
def coverage_override_update(request):
    if request.method != "POST":
        return redirect("coverage_admin")
    if not can_manage_usecases(request.user, None):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    framework = request.POST.get("framework", "").strip().upper()
    object_type = request.POST.get("object_type", "").strip().lower()
    object_key = request.POST.get("object_key", "").strip()
    object_name = request.POST.get("object_name", "").strip()
    status = request.POST.get("status", "").strip()
    reason = request.POST.get("reason", "").strip()
    default_enabled = request.POST.get("default_enabled") == "1"
    next_url = request.POST.get("next") or reverse("coverage_admin")

    valid_frameworks = {CoverageOverride.FRAMEWORK_ATTACK, CoverageOverride.FRAMEWORK_D3FEND}
    valid_types = {CoverageOverride.OBJECT_TACTIC, CoverageOverride.OBJECT_TECHNIQUE, CoverageOverride.OBJECT_CATEGORY}
    valid_statuses = {CoverageOverride.STATUS_ENABLED, CoverageOverride.STATUS_FULFILLED, CoverageOverride.STATUS_DISABLED}

    if framework not in valid_frameworks or object_type not in valid_types or status not in valid_statuses or not object_key:
        messages.error(request, "No se pudo actualizar la cobertura: datos inválidos.")
        return redirect(next_url)

    if status in {CoverageOverride.STATUS_FULFILLED, CoverageOverride.STATUS_DISABLED} and not reason:
        messages.error(request, "Indicá el motivo/evidencia antes de guardar ese estado.")
        return redirect(next_url)

    # Si vuelve al estado normal y el catálogo original ya estaba habilitado, no
    # hace falta guardar override: limpiamos la excepción y queda mantenible.
    if status == CoverageOverride.STATUS_ENABLED and default_enabled:
        CoverageOverride.objects.filter(
            framework=framework,
            object_type=object_type,
            object_key=object_key,
        ).delete()
        messages.success(request, "Cobertura restablecida a Habilitada.")
        return redirect(next_url)

    override, _ = CoverageOverride.objects.update_or_create(
        framework=framework,
        object_type=object_type,
        object_key=object_key,
        defaults={
            "object_name": object_name,
            "status": status,
            "reason": reason,
            "updated_by": request.user,
        },
    )
    messages.success(request, f"Cobertura actualizada: {override.get_status_display()}.")
    return redirect(next_url)


@login_required
def usecase_list(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    legacy_query = request.GET.copy()
    legacy_query.pop("saved_only", None)
    legacy_query.pop("updated_ids", None)
    legacy_query.pop("updated", None)
    legacy_query.pop("status", None)
    if legacy_query.urlencode() != request.GET.urlencode():
        return _redirect_usecase_list_with_query(legacy_query.urlencode())

    # _get_filtered_usecases returns (queryset, filters) — unpack correctly.
    qs, filters = _get_filtered_usecases(request, with_prefetch=True)

    q              = filters["q"]
    status         = filters["status"]
    device         = filters["device"]
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

    devices = (
        UseCase.objects.filter(status__iexact=PRODUCTION_STATUS).exclude(device="")
        .values_list("device", flat=True).distinct().order_by("device")
    )
    owners = (
        UseCase.objects.filter(status__iexact=PRODUCTION_STATUS).exclude(owner_name="")
        .values_list("owner_name", flat=True).distinct().order_by("owner_name")
    )

    selected_mitre  = MitreAttack.objects.filter(id=int(mitre_id)).first()  if mitre_id.isdigit()  else None
    selected_d3fend = D3Fend.objects.filter(id=int(d3fend_id)).first()      if d3fend_id.isdigit() else None

    today      = date.today()
    soon_limit = today + timedelta(days=30)

    quick_base_qs, _ = _get_filtered_usecases(request, with_prefetch=False, ignore_quick=True)

    production_total       = quick_base_qs.count()
    visible_total          = qs.count()
    visible_enabled        = quick_base_qs.filter(is_enabled=True).count()
    visible_critical       = quick_base_qs.filter(severity__iexact="Critical").count()
    visible_overdue        = quick_base_qs.filter(next_review_date__lt=today).count()
    visible_soon           = quick_base_qs.filter(next_review_date__gte=today, next_review_date__lte=soon_limit).count()
    visible_without_attack = quick_base_qs.filter(mitre_attacks__isnull=True).distinct().count()
    visible_without_d3fend = quick_base_qs.filter(d3fends__isnull=True).distinct().count()

    qs = list(qs)
    attack_ids = {attack.id for usecase in qs for attack in usecase.mitre_attacks.all()}
    inferred_d3fends = list(UseCase.inferred_d3fends_for_attack_ids_queryset(attack_ids))
    d3fend_by_attack_id: dict[int, list] = {}
    for d3fend in inferred_d3fends:
        for attack in d3fend.related_attacks.all():
            if attack.is_enabled:
                d3fend_by_attack_id.setdefault(attack.id, []).append(d3fend)

    # Resolve user roles once — avoids N*2 group DB queries in the loop below.
    roles = resolve_user_roles(request.user)

    for usecase in qs:
        seen_ids, inferred_for = set(), []
        for attack in usecase.mitre_attacks.all():
            for d3fend in d3fend_by_attack_id.get(attack.id, []):
                if d3fend.id not in seen_ids:
                    seen_ids.add(d3fend.id)
                    inferred_for.append(d3fend)
        inferred_for.sort(key=lambda item: (item.code, item.name))
        usecase.inferred_d3fends   = inferred_for
        usecase.can_manage_by_user = can_manage_usecases(request.user, usecase, _roles=roles)
        usecase.can_delete_by_user = can_delete_usecases(request.user, usecase, _roles=roles)

    context = {
        "usecases":                qs,
        "q":                       q,
        "selected_status":         status,
        "selected_device":         device,
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
        "owners":                  owners,
        "severity_choices":        UseCase.SEVERITY_CHOICES,
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
        "Nombre", "Dispositivo", "Responsable desarrollo", "Estado", "Severidad",
        "Ultimo control", "Proximo control", "Habilitado", "Motivo deshabilitación", "ATT&CK", "D3FEND",
    ])
    for uc in qs:
        writer.writerow([
            uc.name, uc.device, uc.owner_name, uc.status, uc.severity,
            uc.last_validation_date or "", uc.next_review_date or "",
            "Si" if uc.is_enabled else "No", uc.disabled_reason or "",
            _serialize_mitre(uc), _serialize_d3fend(uc),
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
            usecase.sync_d3fends_from_attacks()
            messages.success(request, "Caso de uso creado correctamente.")
            return redirect("usecase_detail", pk=usecase.pk)
    else:
        form = UseCaseForm()

    return render(request, "usecases/usecase_form.html", {"form": form, "title": "Nuevo caso de uso"})


@login_required
def usecase_edit(request, pk):
    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends"), pk=pk,
    )
    if not can_manage_usecases(request.user, usecase):
        return HttpResponseForbidden("Solo podés editar casos de uso propios.")

    old_data = _snapshot_usecase(usecase)

    if request.method == "POST":
        form = UseCaseForm(request.POST, instance=usecase)
        if form.is_valid():
            updated = form.save(commit=False)
            # Preserve lifecycle dates — managed only by the lifecycle review system.
            updated.last_review_date = usecase.last_review_date
            updated.next_review_date = usecase.next_review_date
            updated.updated_by = request.user
            updated.save()
            form.save_m2m()
            updated.sync_d3fends_from_attacks()
            new_data = _snapshot_usecase(updated)
            UseCaseChangeLog.create_diff(updated, old_data, new_data, request.user)
            messages.success(request, "Caso de uso actualizado correctamente.")
            return redirect("usecase_detail", pk=updated.pk)
    else:
        form = UseCaseForm(instance=usecase)

    return render(
        request, "usecases/usecase_form.html",
        {"form": form, "title": "Editar caso de uso", "usecase": usecase},
    )


@login_required
def usecase_detail(request, pk):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends"), pk=pk,
    )

    usecase.inferred_d3fends = list(usecase.inferred_d3fends_queryset())

    change_logs_qs = (
        UseCaseChangeLog.objects
        .filter(use_case=usecase)
        .select_related("changed_by")
        .order_by("-changed_at")
    )
    change_logs_paginator = Paginator(change_logs_qs, 10)
    change_logs_page = change_logs_paginator.get_page(request.GET.get("history_page"))
    change_logs_page_range = change_logs_paginator.get_elided_page_range(
        number=change_logs_page.number,
        on_each_side=2,
        on_ends=1,
    )

    return render(
        request, "usecases/usecase_detail.html",
        {
            "usecase":              usecase,
            "change_logs_page":       change_logs_page,
            "change_logs_page_range": change_logs_page_range,
            "can_manage_usecases":    can_manage_usecases(request.user, usecase),
            "can_delete_usecases":  can_delete_usecases(request.user, usecase),
        },
    )


@login_required
def usecase_quick_update(request, pk):
    if request.method != "POST":
        return redirect("usecase_list")

    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("mitre_attacks", "d3fends"), pk=pk,
    )
    if not can_manage_usecases(request.user, usecase):
        return HttpResponseForbidden("Solo podés actualizar casos de uso propios.")

    old_data = _snapshot_usecase(usecase)

    # Preserve lifecycle dates before any scalar assignment.
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
    messages.success(request, f"Se actualizó '{usecase.name}'.")
    return redirect("usecase_list")


@login_required
def usecase_bulk_update(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    if request.method != "POST":
        return redirect("usecase_list")

    return_qs = request.POST.get("return_qs", "").strip()
    if "changed_ids" in request.POST:
        usecase_ids = _parse_csv_ids(request.POST.get("changed_ids", ""))
    else:
        raw_ids     = request.POST.getlist("uc_ids")
        usecase_ids = [int(x) for x in raw_ids if str(x).isdigit()]

    if not usecase_ids:
        messages.info(request, "No se detectaron cambios para guardar.")
        return _redirect_usecase_list_with_query(return_qs)

    usecases = (
        UseCase.objects
        .filter(pk__in=usecase_ids, status__iexact=PRODUCTION_STATUS)
        .prefetch_related("mitre_attacks", "d3fends")
        .order_by("name")
    )

    # Resolve roles once for the whole bulk operation.
    roles       = resolve_user_roles(request.user)
    updated_count = 0

    with transaction.atomic():
        for usecase in usecases:
            if not can_manage_usecases(request.user, usecase, _roles=roles):
                continue

            pk       = str(usecase.pk)
            old_data = _snapshot_usecase(usecase)

            # Preserve lifecycle dates — bulk form never sends them.
            _saved_last_review = usecase.last_review_date
            _saved_next_review = usecase.next_review_date

            scalar_changes = {
                "owner_name":          request.POST.get(f"owner_name_{pk}", "").strip(),
                "severity":            request.POST.get(f"severity_{pk}", "").strip(),
                "last_validation_date": _parse_date_field(
                    request.POST.get(f"last_validation_date_{pk}", "").strip()
                ),
                "is_enabled": request.POST.get(f"is_enabled_{pk}") == "on",
            }
            # El inventario ya no permite buscar ni pasar casos a estados no productivos.
            # Si por compatibilidad llega status_N desde un template viejo, lo respetamos;
            # si no llega, no tocamos el estado para evitar dejarlo vacío.
            if f"status_{pk}" in request.POST:
                scalar_changes["status"] = request.POST.get(f"status_{pk}", "").strip()
            if f"validation_status_{pk}" in request.POST:
                scalar_changes["validation_status"] = request.POST.get(f"validation_status_{pk}", "").strip()
            if f"validation_result_{pk}" in request.POST:
                scalar_changes["validation_result"] = request.POST.get(f"validation_result_{pk}", "").strip()
            if f"disabled_reason_{pk}" in request.POST:
                scalar_changes["disabled_reason"] = request.POST.get(f"disabled_reason_{pk}", "").strip()

            changed_fields = []
            for field_name, new_value in scalar_changes.items():
                if getattr(usecase, field_name) != new_value:
                    setattr(usecase, field_name, new_value)
                    changed_fields.append(field_name)

            # Restore lifecycle dates after scalar assignments.
            usecase.last_review_date = _saved_last_review
            usecase.next_review_date = _saved_next_review

            current_mitre_ids = {item.id for item in usecase.mitre_attacks.all()}
            posted_mitre_ids  = set(_parse_csv_ids(request.POST.get(f"mitre_attack_ids_{pk}", "")))

            errors = _usecase_business_rule_errors(usecase, mitre_ids=posted_mitre_ids)
            if errors:
                messages.error(request, f"{usecase.name}: " + " ".join(errors))
                continue

            m2m_changed = False
            if current_mitre_ids != posted_mitre_ids:
                usecase.mitre_attacks.set(MitreAttack.objects.filter(id__in=posted_mitre_ids))
                m2m_changed = True
            if usecase.sync_d3fends_from_attacks():
                m2m_changed = True

            if changed_fields or m2m_changed:
                usecase.updated_by = request.user
                if changed_fields:
                    usecase.save()
                else:
                    usecase.save(update_fields=["updated_by", "updated_at"])
                new_data = _snapshot_usecase(usecase)
                UseCaseChangeLog.create_diff(usecase, old_data, new_data, request.user)
                updated_count += 1

    if updated_count:
        messages.success(request, f"Se actualizaron {updated_count} caso(s).")
        return _redirect_usecase_list_with_query(return_qs)

    messages.info(request, "No se detectaron cambios para guardar.")
    return _redirect_usecase_list_with_query(return_qs)


@login_required
def mitre_attack_autocomplete(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    q  = request.GET.get("q", "").strip()
    qs = MitreAttack.objects.filter(is_enabled=True)
    if q:
        qs = qs.filter(Q(external_id__icontains=q) | Q(name__icontains=q) | Q(tactic__icontains=q))

    data = [
        {"id": obj.id, "label": f"{obj.external_id} - {obj.name}",
         "external_id": obj.external_id, "name": obj.name, "tactic": obj.tactic}
        for obj in qs.order_by("external_id", "name")[:20]
    ]
    return JsonResponse({"results": data})


@login_required
def d3fend_autocomplete(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    q  = request.GET.get("q", "").strip()
    qs = D3Fend.objects.filter(is_enabled=True)
    if q:
        qs = qs.filter(Q(code__icontains=q) | Q(name__icontains=q) | Q(category__icontains=q))

    data = [
        {"id": obj.id, "label": f"{obj.code} - {obj.name}",
         "code": obj.code, "name": obj.name, "category": obj.category}
        for obj in qs.order_by("code", "name")[:20]
    ]
    return JsonResponse({"results": data})


@login_required
def lifecycle_management_view(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    today            = date.today()
    cycle_start, cycle_end = current_lifecycle_window(today)
    only_pending     = request.GET.get("only_pending") == "1"
    lifecycle_admin  = user_is_lifecycle_admin(request.user)

    usecases = list(UseCase.objects.select_related("lifecycle_control_owner").filter(status__iexact=UseCase.STATUS_PRODUCTION).order_by("name"))

    User = get_user_model()
    lifecycle_users = (
        User.objects.filter(is_active=True).order_by("username")
        if lifecycle_admin else User.objects.none()
    )

    # Resolve roles once — can_finish_lifecycle_review and can_assign_lifecycle_owner
    # each call is_admin_role / user_in_group, which hits the DB without caching.
    roles                = resolve_user_roles(request.user)
    can_finish_cache     = can_finish_lifecycle_review(request.user, None, _roles=roles) if lifecycle_admin else None
    can_assign           = can_assign_lifecycle_owner(request.user, _roles=roles)

    rows                 = []
    completed_in_cycle   = 0
    owner_pending_counter = Counter()

    for uc in usecases:
        last_check = uc.last_validation_date
        completed  = bool(last_check and cycle_start <= last_check <= cycle_end)
        if completed:
            completed_in_cycle += 1

        review_days = uc.days_until_review
        if review_days is None:
            review_badge, review_level = "Sin fecha", "neutral"
        elif review_days < 0:
            review_badge, review_level = f"Vencido ({abs(review_days)}d)", "danger"
        elif review_days <= 15:
            review_badge, review_level = f"Por vencer ({review_days}d)", "warn"
        else:
            review_badge, review_level = f"Al día ({review_days}d)", "ok"

        is_pending = not completed
        if is_pending:
            owner_key = (
                uc.lifecycle_control_owner.get_full_name() or uc.lifecycle_control_owner.username
                if uc.lifecycle_control_owner else "Sin responsable de control"
            )
            owner_pending_counter[owner_key] += 1

        if only_pending and not is_pending:
            continue

        # Per-row can_finish: admins already resolved; non-admins check ownership only.
        if lifecycle_admin:
            can_finish_row = True
        else:
            can_finish_row = (
                not roles["is_readonly"]
                and (roles["is_analyst"] or request.user.has_perm("usecases.add_lifecyclereview"))
                and uc.lifecycle_control_owner_id == request.user.id
            )

        rows.append({
            "usecase":          uc,
            "last_check":       last_check,
            "next_check":       uc.next_review_date,
            "owner":            uc.lifecycle_control_owner,
            "task_status":      "Finalizada" if completed else "Pendiente",
            "is_pending":       is_pending,
            "can_finish":       can_finish_row,
            "can_assign_owner": can_assign,
            "review_badge":     review_badge,
            "review_level":     review_level,
        })

    total     = len(usecases)
    pending   = total - completed_in_cycle
    days_left = (cycle_end - today).days

    context = {
        "rows":                rows,
        "cycle_start":         cycle_start,
        "cycle_end":           cycle_end,
        "summary_total":       total,
        "summary_completed":   completed_in_cycle,
        "summary_pending":     pending,
        "summary_days_left":   days_left,
        "only_pending":        only_pending,
        "owner_pending_summary": owner_pending_counter.most_common(5),
        "lifecycle_users":     lifecycle_users,
        "can_manage_lifecycle": lifecycle_admin,
        "lifecycle_scope_label": (
            "Solo casos en Producción" if lifecycle_admin
            else "Solo casos en Producción · solo podés finalizar los asignados a vos"
        ),
    }
    return render(request, "usecases/lifecycle_management.html", context)


@login_required
def lifecycle_mark_done(request, pk):
    if request.method != "POST":
        return redirect("lifecycle_management")

    uc = get_object_or_404(UseCase, pk=pk)
    if not can_finish_lifecycle_review(request.user, uc):
        return HttpResponseForbidden(
            "Solo el responsable de control asignado o un administrador puede finalizar esta revisión."
        )

    old_data = _snapshot_usecase(uc)
    if can_assign_lifecycle_owner(request.user):
        owner_id = request.POST.get("lifecycle_control_owner", "").strip()
        if owner_id.isdigit():
            uc.lifecycle_control_owner_id = int(owner_id)
        elif owner_id == "":
            uc.lifecycle_control_owner = None

    checked_at = date.today()
    uc.last_validation_date = checked_at
    uc.set_lifecycle_review_dates(checked_at)
    uc.validation_status    = UseCase.VALIDATION_STATUS_FINISHED
    uc.updated_by           = request.user
    uc.save()

    LifecycleReview.objects.create(
        use_case=uc,
        control_owner=uc.lifecycle_control_owner,
        completed_by=request.user,
        status=uc.validation_status,
        result=uc.validation_result,
        checked_at=checked_at,
        next_review_date=uc.next_review_date,
    )
    UseCaseChangeLog.create_diff(uc, old_data, _snapshot_usecase(uc), request.user)
    messages.success(request, f"Ciclo de vida actualizado para '{uc.name}'.")
    return redirect("lifecycle_management")


@login_required
def lifecycle_assign_owner(request, pk):
    if request.method != "POST":
        return redirect("lifecycle_management")

    if not can_assign_lifecycle_owner(request.user):
        return HttpResponseForbidden("Solo administradores pueden reasignar responsables de control.")

    uc       = get_object_or_404(UseCase, pk=pk)
    old_data = _snapshot_usecase(uc)
    owner_id = request.POST.get("lifecycle_control_owner", "").strip()
    if owner_id.isdigit():
        uc.lifecycle_control_owner_id = int(owner_id)
    else:
        uc.lifecycle_control_owner = None
    uc.updated_by = request.user
    uc.save()
    UseCaseChangeLog.create_diff(uc, old_data, _snapshot_usecase(uc), request.user)
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
