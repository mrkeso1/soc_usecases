from django.urls import path

from .views import (
    attack_matrix_view,
    coverage_admin_view,
    coverage_override_update,
    d3fend_autocomplete,
    d3fend_matrix_view,
    inferred_d3fends_for_attacks,
    mitre_attack_autocomplete,
    mitre_attack_subtechniques,
    translation_catalog_export,
    translation_catalog_import,
)


urlpatterns = [
    path("attack-matrix/", attack_matrix_view, name="attack_matrix"),
    path("d3fend-matrix/", d3fend_matrix_view, name="d3fend_matrix"),
    path("coverage-admin/", coverage_admin_view, name="coverage_admin"),
    path("coverage-admin/update/", coverage_override_update, name="coverage_override_update"),
    path("autocomplete/mitre/", mitre_attack_autocomplete, name="mitre_attack_autocomplete"),
    path("autocomplete/mitre/subtechniques/", mitre_attack_subtechniques, name="mitre_attack_subtechniques"),
    path("autocomplete/d3fend/", d3fend_autocomplete, name="d3fend_autocomplete"),
    path("infer-d3fends/", inferred_d3fends_for_attacks, name="infer_d3fends_for_attacks"),
    path("translations/export/", translation_catalog_export, name="mitre_translation_export"),
    path("translations/import/", translation_catalog_import, name="mitre_translation_import"),
]
