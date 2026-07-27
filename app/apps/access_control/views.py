from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from .forms import AccessRoleForm, PERMISSION_CATALOG, UserRoleAssignmentForm


_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."


def _can_manage_access(user, permission="auth.view_group"):
    if getattr(user, "is_superuser", False):
        return True
    if user.groups.filter(name="Admin").exists():
        return True
    return user.has_perm(permission)


@login_required
def admin_console(request):
    if not _can_manage_access(request.user, "auth.view_group"):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    cards = [
        {
            "eyebrow": "Identidad",
            "title": "Accesos y roles",
            "description": "Usuarios, grupos operativos y permisos delegados.",
            "url": reverse("access_control_home"),
            "badge": "Admin",
        },
        {
            "eyebrow": "Inventario",
            "title": "Catálogos de fuentes",
            "description": "Tipos, categorias y subcategorias usadas por Fuentes de eventos.",
            "url": reverse("source_admin_catalog"),
            "badge": "Fuentes",
        },
        {
            "eyebrow": "Inventario",
            "title": "Servidores y nomenclatura",
            "description": "Panel operativo para equipos AD/SIEM, cruces, retención y reglas de nomenclatura.",
            "url": reverse("server_heatmap_administration"),
            "badge": "Heatmap",
        },
        {
            "eyebrow": "Lifecycle",
            "title": "Periodos de control",
            "description": "Fechas manuales de inicio y cierre para los controles de ciclo de vida.",
            "url": reverse("lifecycle_periods_admin"),
            "badge": "Ciclo",
        },
        {
            "eyebrow": "Frameworks",
            "title": "Admin cobertura",
            "description": "Overrides manuales para cobertura ATT&CK y D3FEND.",
            "url": reverse("coverage_admin"),
            "badge": "MITRE",
        },
        {
            "eyebrow": "Reportes",
            "title": "Plantillas PDF",
            "description": "Logo, colores, secciones y metadatos por tipo de reporte.",
            "url": reverse("report_template_settings"),
            "badge": "PDF",
        },
        {
            "eyebrow": "Auditoria",
            "title": "Auditoria central",
            "description": "Línea de tiempo operativa de cambios, seguridad y exportaciones.",
            "url": reverse("audit_list"),
            "badge": "Logs",
        },
        {
            "eyebrow": "Django",
            "title": "Django Admin",
            "description": "Administracion avanzada: LDAP, sync MITRE/D3FEND y modelos internos.",
            "url": "/admin/",
            "badge": "Core",
        },
    ]
    return render(request, "access_control/admin_console.html", {"cards": cards})


@login_required
def access_control_home(request):
    if not _can_manage_access(request.user, "auth.view_group"):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    groups = Group.objects.prefetch_related("permissions", "user_set").order_by("name")
    assignment_form = UserRoleAssignmentForm(request.POST or None)

    if request.method == "POST" and request.POST.get("form_kind") == "assignment":
        if not _can_manage_access(request.user, "accounts.change_user"):
            messages.error(request, "No tenes permisos para asignar roles.")
            return redirect("access_control_home")
        if assignment_form.is_valid():
            user = assignment_form.cleaned_data["user"]
            user.groups.set(assignment_form.cleaned_data["groups"])
            messages.success(request, f"Roles actualizados para {user}.")
            return redirect("access_control_home")

    return render(request, "access_control/access_control.html", {
        "groups": groups,
        "permission_catalog": PERMISSION_CATALOG,
        "assignment_form": assignment_form,
    })


@login_required
def access_role_create(request):
    if not _can_manage_access(request.user, "auth.add_group"):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    form = AccessRoleForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Rol creado.")
        return redirect("access_control_home")
    return render(request, "access_control/role_form.html", {"form": form, "title": "Nuevo rol"})


@login_required
def access_role_edit(request, pk):
    if not _can_manage_access(request.user, "auth.change_group"):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    role = get_object_or_404(Group, pk=pk)
    form = AccessRoleForm(request.POST or None, instance=role)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Rol actualizado.")
        return redirect("access_control_home")
    return render(request, "access_control/role_form.html", {"form": form, "title": f"Editar {role.name}"})
