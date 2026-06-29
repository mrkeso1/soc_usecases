from django.conf import settings
from django.http import Http404
from django.urls import path
from django.views.generic import RedirectView

from .views import (
    download_usecase_import_template,
    export_usecases_csv,
    export_usecases_xlsx,
    import_usecases_excel,
    usecase_inventory_history,
    usecase_bulk_update,
    usecase_create,
    usecase_delete,
    usecase_detail,
    usecase_edit,
    usecase_list,
    usecase_quick_update,
)


def legacy_redirect(pattern_name):
    def view(request, *args, **kwargs):
        if not settings.ENABLE_LEGACY_USECASE_REDIRECTS:
            raise Http404("Ruta legacy deshabilitada.")
        return RedirectView.as_view(pattern_name=pattern_name, permanent=False)(request, *args, **kwargs)

    return view


urlpatterns = [
    path("", usecase_list, name="usecase_list"),
    path("new/", usecase_create, name="usecase_create"),
    path("export/csv/", export_usecases_csv, name="export_usecases_csv"),
    path("export/xlsx/", export_usecases_xlsx, name="export_usecases_xlsx"),
    path("import/excel/", import_usecases_excel, name="import_usecases_excel"),
    path("history/", usecase_inventory_history, name="usecase_inventory_history"),
    path("import/template/", download_usecase_import_template, name="download_usecase_import_template"),
    path("bulk-update/", usecase_bulk_update, name="usecase_bulk_update"),
    path("lifecycle/", legacy_redirect("lifecycle_management")),
    path("lifecycle/<int:pk>/done/", legacy_redirect("lifecycle_management")),
    path("lifecycle/<int:pk>/assign-owner/", legacy_redirect("lifecycle_management")),
    path("attack-matrix/", legacy_redirect("attack_matrix")),
    path("d3fend-matrix/", legacy_redirect("d3fend_matrix")),
    path("coverage-admin/", legacy_redirect("coverage_admin")),
    path("coverage-admin/update/", legacy_redirect("coverage_admin")),
    path("autocomplete/mitre/", legacy_redirect("mitre_attack_autocomplete")),
    path("autocomplete/d3fend/", legacy_redirect("d3fend_autocomplete")),
    path("<int:pk>/", usecase_detail, name="usecase_detail"),
    path("<int:pk>/edit/", usecase_edit, name="usecase_edit"),
    path("<int:pk>/quick-update/", usecase_quick_update, name="usecase_quick_update"),
    path("<int:pk>/delete/", usecase_delete, name="usecase_delete"),
]
