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

urlpatterns = [
    path("", usecase_list, name="usecase_list"),
    path("new/", usecase_create, name="usecase_create"),
    path("export/csv/", export_usecases_csv, name="export_usecases_csv"),
    path("export/xlsx/", export_usecases_xlsx, name="export_usecases_xlsx"),
    path("import/excel/", import_usecases_excel, name="import_usecases_excel"),
    path("history/", usecase_inventory_history, name="usecase_inventory_history"),
    path("import/template/", download_usecase_import_template, name="download_usecase_import_template"),
    path("bulk-update/", usecase_bulk_update, name="usecase_bulk_update"),
    path("lifecycle/", RedirectView.as_view(pattern_name="lifecycle_management", permanent=False)),
    path("lifecycle/<int:pk>/done/", RedirectView.as_view(pattern_name="lifecycle_management", permanent=False)),
    path("lifecycle/<int:pk>/assign-owner/", RedirectView.as_view(pattern_name="lifecycle_management", permanent=False)),
    path("attack-matrix/", RedirectView.as_view(pattern_name="attack_matrix", permanent=False)),
    path("d3fend-matrix/", RedirectView.as_view(pattern_name="d3fend_matrix", permanent=False)),
    path("coverage-admin/", RedirectView.as_view(pattern_name="coverage_admin", permanent=False)),
    path("coverage-admin/update/", RedirectView.as_view(pattern_name="coverage_admin", permanent=False)),
    path("autocomplete/mitre/", RedirectView.as_view(pattern_name="mitre_attack_autocomplete", permanent=False)),
    path("autocomplete/d3fend/", RedirectView.as_view(pattern_name="d3fend_autocomplete", permanent=False)),
    path("<int:pk>/", usecase_detail, name="usecase_detail"),
    path("<int:pk>/edit/", usecase_edit, name="usecase_edit"),
    path("<int:pk>/quick-update/", usecase_quick_update, name="usecase_quick_update"),
    path("<int:pk>/delete/", usecase_delete, name="usecase_delete"),
]
