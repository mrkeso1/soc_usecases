from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse

from apps.mitre.attack_matrix import build_attack_matrix_context
from apps.mitre.coverage_admin import build_coverage_admin_context
from apps.mitre.coverage_overrides import update_coverage_override_from_post
from apps.mitre.d3fend_matrix import build_d3fend_matrix_context
from .models import D3Fend, MitreAttack
from .translation_catalog import export_translation_catalog, import_translation_catalog
from apps.usecases.permissions import can_access_usecases, can_manage_usecases
from apps.usecases.models import UseCase

_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."


@login_required
def attack_matrix_view(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    context = build_attack_matrix_context(request)
    context["can_manage_mitre"] = can_manage_usecases(request.user, None)
    return render(request, "usecases/attack_matrix.html", context)


@login_required
def d3fend_matrix_view(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    context = build_d3fend_matrix_context(request)
    context["can_manage_mitre"] = can_manage_usecases(request.user, None)
    return render(request, "usecases/d3fend_matrix.html", context)


@login_required
def translation_catalog_export(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    response = HttpResponse("\ufeff" + export_translation_catalog(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="mitre_descripciones_castellano.csv"'
    return response


@login_required
def translation_catalog_import(request):
    if request.method != "POST":
        return redirect("attack_matrix")
    if not can_manage_usecases(request.user, None):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    next_view = request.POST.get("next")
    next_view = next_view if next_view in {"attack_matrix", "d3fend_matrix"} else "attack_matrix"
    uploaded_file = request.FILES.get("translation_file")
    if not uploaded_file:
        messages.error(request, "Seleccioná el catálogo CSV traducido.")
        return redirect(next_view)
    try:
        result = import_translation_catalog(uploaded_file)
    except ValueError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(
            request,
            f"Traducciones importadas: {result.updated} actualizadas, "
            f"{result.unchanged} sin cambios y {result.unknown} IDs desconocidos.",
        )
    return redirect(next_view)


@login_required
def coverage_admin_view(request):
    if not can_manage_usecases(request.user, None):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    return render(request, "usecases/coverage_admin.html", build_coverage_admin_context(request.GET))


@login_required
def coverage_override_update(request):
    if request.method != "POST":
        return redirect("coverage_admin")
    if not can_manage_usecases(request.user, None):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    next_url = request.POST.get("next") or reverse("coverage_admin")
    result = update_coverage_override_from_post(request.POST, request.user)
    if result.ok:
        messages.success(request, result.message)
    else:
        messages.error(request, result.message)
    return redirect(next_url)


@login_required
def mitre_attack_autocomplete(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    q = request.GET.get("q", "").strip()
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
def mitre_attack_subtechniques(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    raw_ids = request.GET.getlist("attack_ids")
    if not raw_ids:
        raw_ids = request.GET.get("attack_ids", "").split(",")

    selected_ids = [item for item in raw_ids if str(item).strip().isdigit()]
    selected_attacks = MitreAttack.objects.filter(id__in=selected_ids, is_enabled=True)
    parent_external_ids = [
        attack.external_id
        for attack in selected_attacks
        if attack.external_id and "." not in attack.external_id
    ]
    query = Q(pk__in=[])
    for external_id in parent_external_ids:
        query |= Q(external_id__startswith=f"{external_id}.")

    qs = MitreAttack.objects.filter(query, is_enabled=True).order_by("external_id", "name")
    data = [
        {
            "id": obj.id,
            "label": f"{obj.external_id} - {obj.name}",
            "external_id": obj.external_id,
            "name": obj.name,
            "tactic": obj.tactic,
        }
        for obj in qs
    ]
    return JsonResponse({"results": data})


@login_required
def d3fend_autocomplete(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    q = request.GET.get("q", "").strip()
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
def inferred_d3fends_for_attacks(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    raw_ids = request.GET.getlist("attack_ids")
    if not raw_ids:
        raw_ids = request.GET.get("attack_ids", "").split(",")

    attack_ids = [item for item in raw_ids if str(item).strip().isdigit()]
    qs = UseCase.inferred_d3fends_for_attack_ids_queryset(attack_ids)
    data = [
        {
            "id": obj.id,
            "code": obj.code,
            "name": obj.name,
            "category": obj.category,
            "label": f"{obj.code} - {obj.name}" if obj.name else obj.code,
        }
        for obj in qs
    ]
    return JsonResponse({"results": data})
