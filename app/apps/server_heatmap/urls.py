from django.urls import path

from .views import diagnose_gaps, export_ingestion_gaps, server_heatmap_view, upload_siem_inventory


urlpatterns = [
    path("", server_heatmap_view, name="server_heatmap"),
    path("siem/upload/", upload_siem_inventory, name="server_heatmap_siem_upload"),
    path("gaps/export/", export_ingestion_gaps, name="server_heatmap_gap_export"),
    path("gaps/diagnose/", diagnose_gaps, name="server_heatmap_gap_diagnose"),
]
