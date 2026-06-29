from datetime import date

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.dateparse import parse_date
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from apps.lifecycle.lifecycle import (
    assign_lifecycle_owner,
    build_lifecycle_management_context,
    ensure_configured_periods,
    ensure_cycle,
    lifecycle_completion_errors,
    mark_lifecycle_review_done,
    reset_period,
    start_new_cycle,
)
from apps.lifecycle.models import LifecyclePeriod, LifecyclePeriodMember
from apps.usecases.models import UseCase
from apps.usecases.permissions import (
    can_access_usecases,
    can_assign_lifecycle_owner,
    can_finish_lifecycle_review,
)
from apps.usecases.snapshots import snapshot_usecase

_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."


@login_required
def lifecycle_management_view(request):
    if not can_access_usecases(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    context = build_lifecycle_management_context(request.user, request.GET)
    return render(request, "usecases/lifecycle_management.html", context)


@login_required
def lifecycle_mark_done(request, pk):
    if request.method != "POST":
        return redirect("lifecycle_management")

    usecase = get_object_or_404(UseCase, pk=pk)
    if not can_finish_lifecycle_review(request.user, usecase):
        return HttpResponseForbidden(
            "Solo el responsable de control asignado o un administrador puede finalizar esta revisión."
        )

    errors = lifecycle_completion_errors(usecase, request.POST)
    if errors:
        for error in errors:
            messages.error(request, error)
        return redirect("lifecycle_management")

    mark_lifecycle_review_done(usecase, request.user, request.POST, snapshot_usecase)
    messages.success(request, f"Ciclo de vida actualizado para '{usecase.name}'.")
    return redirect("lifecycle_management")


@login_required
def lifecycle_assign_owner(request, pk):
    if request.method != "POST":
        return redirect("lifecycle_management")

    if not can_assign_lifecycle_owner(request.user):
        return HttpResponseForbidden("Solo administradores pueden reasignar responsables de control.")

    usecase = get_object_or_404(UseCase, pk=pk)
    assign_lifecycle_owner(usecase, request.user, request.POST, snapshot_usecase)
    messages.success(request, f"Responsable de control actualizado para '{usecase.name}'.")
    return redirect("lifecycle_management")


@login_required
def lifecycle_reset_period(request, period):
    if request.method != "POST":
        return redirect("lifecycle_management")
    if not can_assign_lifecycle_owner(request.user):
        return HttpResponseForbidden("Solo administradores pueden reiniciar periodos de ciclo de vida.")

    context = build_lifecycle_management_context(request.user, request.GET)
    year = context["state"]["year"]
    reset_period(year, period, actor=request.user)
    messages.success(request, f"Período C{period} reiniciado. Las revisiones y reportes posteriores fueron invalidados.")
    return redirect("lifecycle_management")


@login_required
def lifecycle_start_cycle(request):
    if request.method != "POST":
        return redirect("lifecycle_management")
    if not can_assign_lifecycle_owner(request.user):
        return HttpResponseForbidden("Solo administradores pueden iniciar ciclos de vida.")

    try:
        cycle = start_new_cycle(request.user)
    except ValueError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, f"Ciclo de vida {cycle.year} iniciado.")
    return redirect("lifecycle_management")


@login_required
def lifecycle_periods_admin(request):
    if not can_assign_lifecycle_owner(request.user):
        return HttpResponseForbidden("Solo administradores pueden configurar periodos de ciclo de vida.")

    year = date.today().year
    cycle = ensure_cycle(year, actor=request.user)
    ensure_configured_periods(cycle)

    if request.method == "POST":
        action = request.POST.get("action", "")
        if action == "add":
            _add_lifecycle_period(request, cycle)
        elif action == "update":
            _update_lifecycle_period(request, cycle)
        elif action == "delete":
            _delete_lifecycle_period(request, cycle)
        else:
            messages.error(request, "Acción no reconocida.")
        return redirect("lifecycle_periods_admin")

    periods = cycle.configured_periods.order_by("period", "start_date")
    return render(request, "usecases/lifecycle_periods_admin.html", {
        "cycle": cycle,
        "periods": periods,
    })


def _parse_period_dates(request):
    start = parse_date(request.POST.get("start_date", "").strip())
    end = parse_date(request.POST.get("end_date", "").strip())
    if not start or not end:
        messages.error(request, "Carga fecha de inicio y fecha de cierre válidas.")
        return None, None
    if end < start:
        messages.error(request, "La fecha de cierre no puede ser anterior a la fecha de inicio.")
        return None, None
    return start, end


def _add_lifecycle_period(request, cycle):
    label = request.POST.get("label", "").strip()
    start, end = _parse_period_dates(request)
    if not label or not start or not end:
        if not label:
            messages.error(request, "Carga un nombre para el periodo.")
        return
    next_period = (cycle.configured_periods.order_by("-period").values_list("period", flat=True).first() or 0) + 1
    LifecyclePeriod.objects.create(
        cycle=cycle,
        period=next_period,
        label=label,
        start_date=start,
        end_date=end,
        is_active=True,
    )
    messages.success(request, f"Periodo '{label}' agregado.")


def _update_lifecycle_period(request, cycle):
    period = get_object_or_404(LifecyclePeriod, pk=request.POST.get("period_id"), cycle=cycle)
    label = request.POST.get("label", "").strip()
    start, end = _parse_period_dates(request)
    if not label or not start or not end:
        if not label:
            messages.error(request, "Carga un nombre para el periodo.")
        return
    period.label = label
    period.start_date = start
    period.end_date = end
    period.is_active = request.POST.get("is_active") == "on"
    period.save(update_fields=["label", "start_date", "end_date", "is_active", "updated_at"])
    messages.success(request, f"Periodo '{period.label}' actualizado.")


def _delete_lifecycle_period(request, cycle):
    period = get_object_or_404(LifecyclePeriod, pk=request.POST.get("period_id"), cycle=cycle)
    LifecyclePeriodMember.objects.filter(year=cycle.year, period=period.period).delete()
    label = period.label
    period.delete()
    messages.success(request, f"Periodo '{label}' eliminado.")
