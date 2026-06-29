from django.urls import path

from .views import (
    sigma_workspace,
    technical_backup_create,
    technical_backup_detail,
    technical_backup_from_usecase_rule,
    technical_backup_list,
)


urlpatterns = [
    path("epl-to-sigma/", sigma_workspace, {"mode": "epl"}, name="sigma_epl_to_sigma"),
    path("converter/", sigma_workspace, {"mode": "converter"}, name="sigma_converter"),
    path("backups/", technical_backup_list, name="technical_backup_list"),
    path("backups/new/", technical_backup_create, name="technical_backup_create"),
    path("backups/from-usecase/<int:use_case_pk>/", technical_backup_from_usecase_rule, name="technical_backup_from_usecase_rule"),
    path("backups/<int:pk>/", technical_backup_detail, name="technical_backup_detail"),
]
