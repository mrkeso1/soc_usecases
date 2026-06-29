from django.urls import path

from .views import report_download, report_index, report_preview, report_preview_pdf, report_template_settings


urlpatterns = [
    path("", report_index, name="report_index"),
    path("template/", report_template_settings, name="report_template_settings"),
    path("<str:report_type>/preview/pdf/", report_preview_pdf, name="report_preview_pdf"),
    path("<str:report_type>/preview/", report_preview, name="report_preview"),
    path("<str:report_type>/download/", report_download, name="report_download"),
]
