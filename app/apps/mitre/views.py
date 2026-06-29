from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse

from apps.mitre.attack_matrix import build_attack_matrix_context
from apps.mitre.coverage_admin import build_coverage_admin_context
from apps.mitre.coverage_overrides import update_coverage_override_from_post
from apps.mitre.d3fend_matrix import build_d3fend_matrix_context
from .models import D3Fend, MitreAttack
from apps.usecases.permissions import can_access_usecases, can_manage_usecases

_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."


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
