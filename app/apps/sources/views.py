from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import ProtectedError
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from .forms import EventSourceForm, SourceCategoryForm, SourceDeliveryMethodForm, SourceSubcategoryForm, SourceTypeForm, UseCaseSourceForm
from .models import EventSource, SourceCategory, SourceDeliveryMethod, SourceType, UseCaseSource
from .permissions import can_access_sources, can_manage_sources


_FORBIDDEN_MSG = "No tenes permisos para acceder a fuentes."


def _source_subcategory_options():
    return list(
        SourceCategory.objects.filter(parent__isnull=False, is_active=True)
        .select_related("parent")
        .order_by("parent__name", "name")
        .values("id", "parent_id", "name")
    )


@login_required
def source_list(request):
    if not can_access_sources(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    q = request.GET.get("q", "").strip()
    status = request.GET.get("status", "").strip()
    source_type = request.GET.get("source_type", "").strip()
    category = request.GET.get("category", "").strip()
    delivery_method = request.GET.get("delivery_method", "").strip()
    port = request.GET.get("port", "").strip()
    protocol = request.GET.get("protocol", "").strip()
    service_account = request.GET.get("service_account", "").strip()
    host = request.GET.get("host", "").strip()
    sort = request.GET.get("sort", "source").strip()
    direction = request.GET.get("direction", "asc").strip()
    sort_fields = {
        "source": "name",
        "protection": "protection",
        "type": "source_type",
        "taxonomy": "category_ref__name",
        "delivery_method": "delivery_method__name",
        "port": "port",
        "protocol": "protocol",
        "service_account": "service_account",
        "host": "host",
        "status": "status",
        "cases": "usecase_count",
    }
    if sort not in sort_fields:
        sort = "source"
    if direction not in {"asc", "desc"}:
        direction = "asc"

    qs = EventSource.objects.select_related("category_ref", "subcategory_ref", "delivery_method").annotate(
        usecase_count=Count("use_case_links", distinct=True)
    )
    if q:
        qs = qs.filter(
            Q(code__icontains=q)
            | Q(name__icontains=q)
            | Q(vendor__icontains=q)
            | Q(product__icontains=q)
            | Q(host__icontains=q)
            | Q(protocol__icontains=q)
            | Q(service_account__icontains=q)
            | Q(delivery_method__name__icontains=q)
            | Q(owner__icontains=q)
            | Q(category_ref__name__icontains=q)
            | Q(subcategory_ref__name__icontains=q)
        )
    if status:
        qs = qs.filter(status=status)
    if source_type:
        qs = qs.filter(source_type=source_type)
    if category.isdigit():
        qs = qs.filter(Q(category_ref_id=int(category)) | Q(subcategory_ref_id=int(category)))
    if delivery_method.isdigit():
        qs = qs.filter(delivery_method_id=int(delivery_method))
    if port.isdigit():
        qs = qs.filter(port=int(port))
    if protocol:
        qs = qs.filter(protocol__iexact=protocol)
    if service_account:
        qs = qs.filter(service_account__icontains=service_account)
    if host:
        qs = qs.filter(host__icontains=host)

    order_field = sort_fields[sort]
    if direction == "desc":
        order_field = f"-{order_field}"
    paginator = Paginator(qs.order_by(order_field, "name"), 25)
    page = paginator.get_page(request.GET.get("page"))

    return render(request, "sources/source_list.html", {
        "sources": page,
        "q": q,
        "selected_status": status,
        "selected_source_type": source_type,
        "selected_category": category,
        "selected_delivery_method": delivery_method,
        "selected_port": port,
        "selected_protocol": protocol,
        "selected_service_account": service_account,
        "selected_host": host,
        "selected_sort": sort,
        "selected_direction": direction,
        "status_choices": EventSource.STATUS_CHOICES,
        "type_choices": SourceType.objects.filter(is_active=True).order_by("name").values_list("code", "name"),
        "category_choices": SourceCategory.objects.filter(is_active=True).select_related("parent").order_by("parent__name", "name"),
        "delivery_method_choices": SourceDeliveryMethod.objects.filter(is_active=True).order_by("name"),
        "protocol_choices": EventSource.objects.exclude(protocol="").order_by("protocol").values_list("protocol", flat=True).distinct(),
        "total_sources": EventSource.objects.count(),
        "active_sources": EventSource.objects.filter(status=EventSource.STATUS_ACTIVE).count(),
        "linked_sources": EventSource.objects.filter(use_case_links__isnull=False).distinct().count(),
        "can_manage_sources": can_manage_sources(request.user),
    })


@login_required
def source_admin_catalog(request):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para administrar fuentes.")

    categories = SourceCategory.objects.select_related("parent").annotate(
        direct_source_count=Count("sources", distinct=True),
        subcategory_source_count=Count("subcategory_sources", distinct=True),
    ).order_by("parent__name", "name")
    source_type_qs = SourceType.objects.order_by("name")
    delivery_method_qs = SourceDeliveryMethod.objects.order_by("name")
    type_paginator = Paginator(source_type_qs, 20)
    method_paginator = Paginator(delivery_method_qs, 20)
    type_page = type_paginator.get_page(request.GET.get("types_page"))
    method_page = method_paginator.get_page(request.GET.get("methods_page"))
    type_rows = []
    for item in type_page:
        item.source_count = EventSource.objects.filter(source_type=item.code).count()
        type_rows.append(item)
    method_rows = []
    for item in method_page:
        item.source_count = EventSource.objects.filter(delivery_method=item).count()
        method_rows.append(item)

    return render(request, "sources/source_admin_catalog.html", {
        "categories": categories,
        "source_types": type_rows,
        "source_types_page": type_page,
        "source_type_count": source_type_qs.count(),
        "delivery_methods": method_rows,
        "delivery_methods_page": method_page,
        "delivery_method_count": delivery_method_qs.count(),
        "source_count": EventSource.objects.count(),
    })


@login_required
def source_category_create(request):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar categorías.")

    form = SourceCategoryForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Categoría creada correctamente.")
        return redirect("source_admin_catalog")
    return render(request, "sources/source_catalog_form.html", {
        "form": form,
        "title": "Nueva categoria principal",
        "subtitle": "Crea una categoria raiz. No lleva padre; despues podes crear subcategorias debajo.",
        "back_url_name": "source_admin_catalog",
    })


@login_required
def source_subcategory_create(request):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para administrar subcategorias.")

    form = SourceSubcategoryForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Subcategoria creada correctamente.")
        return redirect("source_admin_catalog")
    return render(request, "sources/source_catalog_form.html", {
        "form": form,
        "title": "Nueva subcategoria",
        "subtitle": "Crea una subcategoria asociada a una categoria principal existente.",
        "back_url_name": "source_admin_catalog",
    })


@login_required
def source_category_edit(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar categorías.")

    category = get_object_or_404(SourceCategory, pk=pk)
    form_class = SourceSubcategoryForm if category.parent_id else SourceCategoryForm
    form = form_class(request.POST or None, instance=category)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Categoría actualizada correctamente.")
        return redirect("source_admin_catalog")
    return render(request, "sources/source_catalog_form.html", {
        "form": form,
        "title": f"Editar {'subcategoria' if category.parent_id else 'categoria principal'}",
        "subtitle": str(category),
        "back_url_name": "source_admin_catalog",
    })


@login_required
def source_category_delete(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenés permisos para administrar categorías.")
    if request.method != "POST":
        return redirect("source_admin_catalog")

    category = get_object_or_404(SourceCategory, pk=pk)
    try:
        category.delete()
    except ProtectedError:
        category.is_active = False
        category.save(update_fields=["is_active", "updated_at"])
        messages.warning(request, "La categoría está en uso; fue desactivada para nuevas altas.")
    else:
        messages.success(request, "Categoría eliminada.")
    return redirect("source_admin_catalog")


@login_required
def source_type_create(request):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para administrar tipos.")

    form = SourceTypeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Tipo creado correctamente.")
        return redirect("source_admin_catalog")
    return render(request, "sources/source_catalog_form.html", {
        "form": form,
        "title": "Nuevo tipo de fuente",
        "back_url_name": "source_admin_catalog",
    })


@login_required
def source_type_edit(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para administrar tipos.")

    source_type = get_object_or_404(SourceType, pk=pk)
    form = SourceTypeForm(request.POST or None, instance=source_type)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Tipo actualizado correctamente.")
        return redirect("source_admin_catalog")
    return render(request, "sources/source_catalog_form.html", {
        "form": form,
        "title": f"Editar {source_type.name}",
        "back_url_name": "source_admin_catalog",
    })


@login_required
def source_type_delete(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para administrar tipos.")
    if request.method != "POST":
        return redirect("source_admin_catalog")

    source_type = get_object_or_404(SourceType, pk=pk)
    if EventSource.objects.filter(source_type=source_type.code).exists():
        source_type.is_active = False
        source_type.save(update_fields=["is_active", "updated_at"])
        messages.warning(request, "El tipo está en uso; fue desactivado para nuevas altas.")
    else:
        source_type.delete()
        messages.success(request, "Tipo eliminado.")
    return redirect("source_admin_catalog")


@login_required
def source_delivery_method_create(request):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para administrar metodos de envio.")

    form = SourceDeliveryMethodForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Metodo de envio creado correctamente.")
        return redirect("source_admin_catalog")
    return render(request, "sources/source_catalog_form.html", {
        "form": form,
        "title": "Nuevo metodo de envio",
        "back_url_name": "source_admin_catalog",
    })


@login_required
def source_delivery_method_edit(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para administrar metodos de envio.")

    delivery_method = get_object_or_404(SourceDeliveryMethod, pk=pk)
    form = SourceDeliveryMethodForm(request.POST or None, instance=delivery_method)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Metodo de envio actualizado correctamente.")
        return redirect("source_admin_catalog")
    return render(request, "sources/source_catalog_form.html", {
        "form": form,
        "title": f"Editar {delivery_method.name}",
        "back_url_name": "source_admin_catalog",
    })


@login_required
def source_delivery_method_delete(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para administrar metodos de envio.")
    if request.method != "POST":
        return redirect("source_admin_catalog")

    delivery_method = get_object_or_404(SourceDeliveryMethod, pk=pk)
    if EventSource.objects.filter(delivery_method=delivery_method).exists():
        delivery_method.is_active = False
        delivery_method.save(update_fields=["is_active", "updated_at"])
        messages.warning(request, "El metodo esta en uso; fue desactivado para nuevas altas.")
    else:
        delivery_method.delete()
        messages.success(request, "Metodo de envio eliminado.")
    return redirect("source_admin_catalog")


@login_required
def source_detail(request, pk):
    if not can_access_sources(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    source = get_object_or_404(EventSource.objects.select_related("category_ref", "subcategory_ref", "delivery_method"), pk=pk)
    links = (
        UseCaseSource.objects
        .filter(source=source)
        .select_related("use_case")
        .order_by("use_case__name")
    )
    return render(request, "sources/source_detail.html", {
        "source": source,
        "links": links,
        "can_manage_sources": can_manage_sources(request.user),
    })


@login_required
def source_create(request):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para crear fuentes.")

    if request.method == "POST":
        form = EventSourceForm(request.POST)
        if form.is_valid():
            source = form.save(commit=False)
            source.created_by = request.user
            source.updated_by = request.user
            source.save()
            messages.success(request, "Fuente creada correctamente.")
            return redirect("source_detail", pk=source.pk)
    else:
        form = EventSourceForm()

    return render(request, "sources/source_form.html", {
        "form": form,
        "title": "Nueva fuente",
        "subcategory_options": _source_subcategory_options(),
    })


@login_required
def source_edit(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para editar fuentes.")

    source = get_object_or_404(EventSource, pk=pk)
    if request.method == "POST":
        form = EventSourceForm(request.POST, instance=source)
        if form.is_valid():
            source = form.save(commit=False)
            source.updated_by = request.user
            source.save()
            messages.success(request, "Fuente actualizada correctamente.")
            return redirect("source_detail", pk=source.pk)
    else:
        form = EventSourceForm(instance=source)

    return render(request, "sources/source_form.html", {
        "form": form,
        "source": source,
        "title": "Editar fuente",
        "subcategory_options": _source_subcategory_options(),
    })


@login_required
def source_delete(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para eliminar fuentes.")
    if request.method != "POST":
        return redirect("source_detail", pk=pk)

    source = get_object_or_404(EventSource, pk=pk)
    name = source.display_name
    try:
        source.delete()
    except ProtectedError:
        messages.error(request, "No se puede eliminar una fuente vinculada a casos de uso.")
        return redirect("source_detail", pk=pk)
    messages.success(request, f"Fuente '{name}' eliminada.")
    return redirect("source_list")


@login_required
def usecase_source_create(request):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para vincular fuentes.")

    if request.method == "POST":
        form = UseCaseSourceForm(request.POST)
        if form.is_valid():
            link = form.save(commit=False)
            link.created_by = request.user
            try:
                link.save()
            except IntegrityError:
                form.add_error(None, "Esa fuente ya esta vinculada al caso de uso.")
            else:
                messages.success(request, "Fuente vinculada al caso de uso.")
                next_url = request.POST.get("next") or request.GET.get("next")
                if next_url == "usecase":
                    return redirect("usecase_detail", pk=link.use_case_id)
                return redirect("source_detail", pk=link.source_id)
    else:
        form = UseCaseSourceForm(initial={
            "source": request.GET.get("source", ""),
            "use_case": request.GET.get("use_case", ""),
        })

    return render(request, "sources/usecase_source_form.html", {
        "form": form,
        "title": "Vincular fuente a caso",
        "next": request.GET.get("next", ""),
    })


@login_required
def usecase_source_delete(request, pk):
    if not can_manage_sources(request.user):
        return HttpResponseForbidden("No tenes permisos para desvincular fuentes.")
    if request.method != "POST":
        return redirect("source_list")

    link = get_object_or_404(UseCaseSource, pk=pk)
    source_id = link.source_id
    link.delete()
    messages.success(request, "Fuente desvinculada del caso de uso.")
    return redirect("source_detail", pk=source_id)
