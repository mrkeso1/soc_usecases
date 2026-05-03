from django.urls import path
from .views import (
    usecase_list,
    usecase_detail,
    usecase_edit,
    usecase_quick_update,
    usecase_bulk_update,
    mitre_attack_autocomplete,
    d3fend_autocomplete,
    export_usecases_csv,
)

urlpatterns = [
    path("", usecase_list, name="usecase_list"),
    path("export/csv/", export_usecases_csv, name="export_usecases_csv"),
    path("bulk-update/", usecase_bulk_update, name="usecase_bulk_update"),
    path("autocomplete/mitre/", mitre_attack_autocomplete, name="mitre_attack_autocomplete"),
    path("autocomplete/d3fend/", d3fend_autocomplete, name="d3fend_autocomplete"),
    path("<int:pk>/", usecase_detail, name="usecase_detail"),
    path("<int:pk>/edit/", usecase_edit, name="usecase_edit"),
    path("<int:pk>/quick-update/", usecase_quick_update, name="usecase_quick_update"),
]