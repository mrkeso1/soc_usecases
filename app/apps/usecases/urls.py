from django.urls import path
from .views import (
    usecase_list,
    usecase_detail,
    usecase_create,
    usecase_edit,
    usecase_quick_update,
    usecase_delete,
    usecase_bulk_update,
    mitre_attack_autocomplete,
    d3fend_autocomplete,
    export_usecases_csv,
    lifecycle_management_view,
    lifecycle_mark_done,
    lifecycle_assign_owner,
)

urlpatterns = [
    path("", usecase_list, name="usecase_list"),
    path("new/", usecase_create, name="usecase_create"),
    path("export/csv/", export_usecases_csv, name="export_usecases_csv"),
    path("bulk-update/", usecase_bulk_update, name="usecase_bulk_update"),
    path("lifecycle/", lifecycle_management_view, name="lifecycle_management"),
    path("lifecycle/<int:pk>/done/", lifecycle_mark_done, name="lifecycle_mark_done"),
    path("lifecycle/<int:pk>/assign-owner/", lifecycle_assign_owner, name="lifecycle_assign_owner"),
    path("autocomplete/mitre/", mitre_attack_autocomplete, name="mitre_attack_autocomplete"),
    path("autocomplete/d3fend/", d3fend_autocomplete, name="d3fend_autocomplete"),
    path("<int:pk>/", usecase_detail, name="usecase_detail"),
    path("<int:pk>/edit/", usecase_edit, name="usecase_edit"),
    path("<int:pk>/quick-update/", usecase_quick_update, name="usecase_quick_update"),
    path("<int:pk>/delete/", usecase_delete, name="usecase_delete"),
]