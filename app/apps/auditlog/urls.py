from django.urls import path

from .views import audit_detail, audit_export_csv, audit_export_xlsx, audit_list, audit_timeline_detail


urlpatterns = [
    path("", audit_list, name="audit_list"),
    path("export/csv/", audit_export_csv, name="audit_export_csv"),
    path("export/xlsx/", audit_export_xlsx, name="audit_export_xlsx"),
    path("<str:source>/<int:pk>/", audit_timeline_detail, name="audit_timeline_detail"),
    path("<int:pk>/", audit_detail, name="audit_detail"),
]
