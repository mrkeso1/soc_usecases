from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from apps.auditlog.service import audit
from apps.sources.models import EventSource

from .forms import ControlForm
from .models import Control, ControlInventoryChange
from .services import record_control_change, snapshot_control


def _can_view(user):
    return getattr(user, "is_superuser", False) or user.groups.filter(name__in=["Admin", "Analyst"]).exists() or user.has_perm("controls.view_control")


def _can_change(user):
    return getattr(user, "is_superuser", False) or user.groups.filter(name__in=["Admin", "Analyst"]).exists() or user.has_perm("controls.change_control")


def _can_delete(user):
    return getattr(user, "is_superuser", False) or user.groups.filter(name="Admin").exists() or user.has_perm("controls.delete_control")


@login_required
def control_list(request):
    if not _can_view(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")
    qs = Control.objects.select_related("source").prefetch_related("use_cases")
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(code__icontains=q) | Q(source__name__icontains=q) | Q(objective__icontains=q))
    status = request.GET.get("status", "").strip()
    if status:
        qs = qs.filter(status=status)
    source = request.GET.get("source", "").strip()
    if source.isdigit():
        qs = qs.filter(source_id=int(source))
    items = list(qs[:250])
    return render(request, "controls/control_list.html", {
        "items": items,
        "q": q,
        "selected_status": status,
        "selected_source": source,
        "status_choices": Control.STATUS_CHOICES,
        "sources": EventSource.objects.order_by("name"),
        "total_inventory": Control.objects.count(),
        "inventory_version": ControlInventoryChange.objects.count(),
        "can_change_controls": _can_change(request.user),
        "can_delete_controls": _can_delete(request.user),
    })


@login_required
def control_detail(request, pk):
    if not _can_view(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")
    item = get_object_or_404(Control.objects.select_related("source").prefetch_related("use_cases", "versions"), pk=pk)
    return render(request, "controls/control_detail.html", {"item": item, "can_change_controls": _can_change(request.user)})


@login_required
@transaction.atomic
def control_create(request):
    if not _can_change(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")
    form = ControlForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        item = form.save(commit=False)
        item.created_by = request.user
        item.updated_by = request.user
        item.save()
        form.instance = item
        form.save_m2m()
        record_control_change(item, {}, request.user, ControlInventoryChange.ACTION_CREATED)
        audit(request, "control_created", "control", item.pk, {"name": item.name, "code": item.code})
        messages.success(request, "Control creado.")
        return redirect("control_detail", pk=item.pk)
    return render(request, "controls/control_form.html", {"form": form, "title": "Nuevo control"})


@login_required
@transaction.atomic
def control_edit(request, pk):
    if not _can_change(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")
    item = get_object_or_404(Control, pk=pk)
    previous = snapshot_control(item)
    form = ControlForm(request.POST or None, instance=item)
    if request.method == "POST" and form.is_valid():
        item = form.save(commit=False)
        item.updated_by = request.user
        item.save()
        form.instance = item
        form.save_m2m()
        record_control_change(item, previous, request.user, ControlInventoryChange.ACTION_UPDATED)
        audit(request, "control_updated", "control", item.pk, {"name": item.name, "code": item.code})
        messages.success(request, "Control actualizado.")
        return redirect("control_detail", pk=item.pk)
    return render(request, "controls/control_form.html", {"form": form, "title": f"Editar {item.code}"})


@login_required
@transaction.atomic
def control_delete(request, pk):
    if not _can_delete(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")
    item = get_object_or_404(Control, pk=pk)
    if request.method == "POST":
        audit(request, "control_deleted", "control", item.pk, {"name": item.name, "code": item.code})
        ControlInventoryChange.objects.create(
            action=ControlInventoryChange.ACTION_DELETED,
            control_code=item.code,
            control_name=item.name,
            control_version=item.version,
            actor=request.user,
        )
        item.delete()
        messages.success(request, "Control eliminado.")
        return redirect("control_list")
    return render(request, "controls/control_confirm_delete.html", {"item": item})


@login_required
def control_history(request):
    if not _can_view(request.user):
        return HttpResponseForbidden("No tenes permisos para acceder a esta seccion.")
    return redirect("/audit/?area=controls")
