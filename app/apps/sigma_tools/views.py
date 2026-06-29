from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Exists, OuterRef, Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.auditlog.service import audit
from apps.usecases.models import UseCase

from .forms import SigmaConversionForm
from .models import SigmaConversion, UseCaseTechnicalBackup
from .services import build_inventory_rule_backup_payload, epl_to_sigma, sigma_to_rule, sync_inventory_rule_backup


_FORBIDDEN_MSG = "No tenes permisos para acceder a esta seccion."


def _can_run_sigma(user):
    return (
        getattr(user, "is_superuser", False)
        or user.groups.filter(name__in=["Admin", "Analyst"]).exists()
        or user.has_perm("sigma_tools.add_sigmaconversion")
        or user.has_perm("sigma_tools.run_sigmaconversion")
    )


def _can_manage_backups(user):
    return (
        getattr(user, "is_superuser", False)
        or user.groups.filter(name__in=["Admin", "Analyst"]).exists()
        or user.has_perm("sigma_tools.manage_technicalbackup")
        or user.has_perm("sigma_tools.add_usecasetechnicalbackup")
    )


def _create_backup_from_conversion(conversion):
    if not conversion.use_case_id:
        return None
    if conversion.mode == SigmaConversion.MODE_EPL_TO_SIGMA:
        backup_type = UseCaseTechnicalBackup.TYPE_BOTH
        logic_text = conversion.input_text
        sigma_text = conversion.output_text
    else:
        backup_type = UseCaseTechnicalBackup.TYPE_BOTH
        logic_text = conversion.output_text
        sigma_text = conversion.input_text
    return UseCaseTechnicalBackup.objects.create(
        use_case=conversion.use_case,
        backup_type=backup_type,
        title=f"Backup desde {conversion.get_mode_display()}",
        logic_text=logic_text,
        sigma_text=sigma_text,
        source_conversion=conversion,
        created_by=conversion.created_by,
        notes="Generado automáticamente desde Sigma Tools.",
    )


@login_required
def sigma_workspace(request, mode="epl"):
    if not _can_run_sigma(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    form = SigmaConversionForm(request.POST or None)
    result = ""
    mode = "converter" if mode == "converter" else "epl"
    if request.method == "POST" and form.is_valid():
        if mode == "converter":
            result = sigma_to_rule(form.cleaned_data["input_text"], form.cleaned_data["target"])
            conversion_mode = SigmaConversion.MODE_SIGMA_TO_TARGET
            success_message = "Regla Sigma convertida al destino seleccionado."
        else:
            result = epl_to_sigma(form.cleaned_data["input_text"])
            conversion_mode = SigmaConversion.MODE_EPL_TO_SIGMA
            success_message = "EPL convertido a Sigma."

        conversion = SigmaConversion.objects.create(
            use_case=form.cleaned_data["use_case"],
            mode=conversion_mode,
            target=form.cleaned_data["target"] if mode == "converter" else "",
            input_text=form.cleaned_data["input_text"],
            output_text=result,
            created_by=request.user,
        )
        backup = _create_backup_from_conversion(conversion)
        audit(
            request,
            "sigma_rule_converted" if mode == "converter" else "sigma_epl_converted",
            "sigma_conversion",
            form.cleaned_data["use_case"].pk if form.cleaned_data["use_case"] else "",
            {
                "mode": mode,
                "target": form.cleaned_data["target"] if mode == "converter" else "sigma",
                "technical_backup_id": backup.pk if backup else "",
            },
        )
        messages.success(request, success_message)

    return render(request, "sigma_tools/workspace.html", {
        "form": form,
        "result": result,
        "mode": mode,
    })


@login_required
def technical_backup_list(request):
    if not _can_run_sigma(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    q = request.GET.get("q", "").strip()
    backup_exists = UseCaseTechnicalBackup.objects.filter(use_case=OuterRef("pk"), is_current=True)
    cases = UseCase.objects.annotate(has_current_backup=Exists(backup_exists))
    total_cases = cases.count()
    backed_cases = cases.filter(has_current_backup=True).count()
    missing_cases = cases.filter(has_current_backup=False).order_by("name")[:20]

    backups = UseCaseTechnicalBackup.objects.select_related("use_case", "created_by").order_by("use_case__name", "-version")
    if q:
        backups = backups.filter(
            Q(use_case__name__icontains=q)
            | Q(title__icontains=q)
            | Q(checksum__icontains=q)
            | Q(notes__icontains=q)
        )
    paginator = Paginator(backups, 25)
    page = paginator.get_page(request.GET.get("page"))

    return render(request, "sigma_tools/backup_list.html", {
        "backups": page,
        "q": q,
        "total_cases": total_cases,
        "backed_cases": backed_cases,
        "missing_count": max(total_cases - backed_cases, 0),
        "coverage_percent": round((backed_cases / total_cases) * 100) if total_cases else 0,
        "missing_cases": missing_cases,
        "can_manage_backups": _can_manage_backups(request.user),
    })


@login_required
def technical_backup_create(request):
    if not _can_manage_backups(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    messages.info(
        request,
        "Los backups tecnicos se generan automaticamente al guardar la regla del inventario.",
    )
    use_case_id = request.GET.get("use_case", "")
    if use_case_id.isdigit():
        return redirect("usecase_edit", pk=use_case_id)
    return redirect("technical_backup_list")


@login_required
@require_POST
def technical_backup_from_usecase_rule(request, use_case_pk):
    if not _can_manage_backups(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)

    usecase = get_object_or_404(
        UseCase.objects.prefetch_related("rule_conditions"),
        pk=use_case_pk,
    )
    initial = build_inventory_rule_backup_payload(usecase)
    logic_text = (initial.get("logic_text") or "").strip()
    if not logic_text:
        messages.warning(request, "Primero carga una regla completa o condiciones en el inventario.")
        return redirect("usecase_edit", pk=usecase.pk)

    backup, created = sync_inventory_rule_backup(usecase, request.user)
    if created:
        audit(
            request,
            "technical_backup_created_from_inventory_rule",
            "technical_backup",
            backup.pk,
            {"use_case_id": backup.use_case_id, "version": backup.version, "checksum": backup.checksum},
        )
        messages.success(request, "Backup tecnico generado desde la regla del inventario.")
    else:
        messages.info(request, "El backup vigente ya coincide con la regla actual del inventario.")
    return redirect("technical_backup_detail", pk=backup.pk)


@login_required
def technical_backup_detail(request, pk):
    if not _can_run_sigma(request.user):
        return HttpResponseForbidden(_FORBIDDEN_MSG)
    backup = get_object_or_404(
        UseCaseTechnicalBackup.objects.select_related("use_case", "created_by", "source_conversion"),
        pk=pk,
    )
    versions = UseCaseTechnicalBackup.objects.filter(use_case=backup.use_case).order_by("-version")
    return render(request, "sigma_tools/backup_detail.html", {
        "backup": backup,
        "versions": versions,
        "can_manage_backups": _can_manage_backups(request.user),
    })
