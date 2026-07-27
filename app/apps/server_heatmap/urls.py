from django.urls import path

from .views import (
    diagnose_gaps,
    delete_naming_rule,
    delete_server_category,
    edit_naming_rule,
    edit_server_asset,
    edit_server_category,
    export_ingestion_gaps,
    inventory_filter_create,
    inventory_filter_delete,
    inventory_filter_edit,
    inventory_filter_list,
    reprocess_inventory,
    server_heatmap_view,
    server_administration,
    server_asset_results,
    server_naming_rules,
    server_sections,
    upload_siem_inventory,
)


urlpatterns = [
    path("", server_heatmap_view, name="server_heatmap"),
    path("siem/upload/", upload_siem_inventory, name="server_heatmap_siem_upload"),
    path("gaps/export/", export_ingestion_gaps, name="server_heatmap_gap_export"),
    path("gaps/diagnose/", diagnose_gaps, name="server_heatmap_gap_diagnose"),
    path("reprocess/", reprocess_inventory, name="server_heatmap_reprocess"),
    path("administration/", server_administration, name="server_heatmap_administration"),
    path(
        "administration/assets/results/",
        server_asset_results,
        name="server_heatmap_asset_results",
    ),
    path(
        "administration/sections/",
        server_sections,
        name="server_heatmap_sections",
    ),
    path(
        "administration/naming-rules/",
        server_naming_rules,
        name="server_heatmap_naming_rules",
    ),
    path("administration/rules/<int:rule_id>/", edit_naming_rule, name="server_heatmap_rule_edit"),
    path(
        "administration/rules/<int:rule_id>/delete/",
        delete_naming_rule,
        name="server_heatmap_rule_delete",
    ),
    path(
        "administration/assets/<int:asset_id>/",
        edit_server_asset,
        name="server_heatmap_asset_edit",
    ),
    path(
        "administration/categories/<int:category_id>/",
        edit_server_category,
        name="server_heatmap_category_edit",
    ),
    path(
        "administration/categories/<int:category_id>/delete/",
        delete_server_category,
        name="server_heatmap_category_delete",
    ),
    path(
        "administration/filters/",
        inventory_filter_list,
        name="server_heatmap_filter_list",
    ),
    path(
        "administration/filters/new/",
        inventory_filter_create,
        name="server_heatmap_filter_create",
    ),
    path(
        "administration/filters/<int:rule_id>/",
        inventory_filter_edit,
        name="server_heatmap_filter_edit",
    ),
    path(
        "administration/filters/<int:rule_id>/delete/",
        inventory_filter_delete,
        name="server_heatmap_filter_delete",
    ),
]
