from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect
from django.urls import include, path, re_path
from django.views.static import serve

from apps.dashboard.views import dashboard_mitre_view, dashboard_pdf_export, dashboard_view


def root_redirect(request):
    return redirect("dashboard")


urlpatterns = [
    path("admin/", admin.site.urls),
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="registration/login.html"),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(next_page="login"), name="logout"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("dashboard/mitre/", dashboard_mitre_view, name="dashboard_mitre"),
    path("dashboard/export/pdf/", dashboard_pdf_export, name="dashboard_pdf_export"),
    path("lifecycle/", include("apps.lifecycle.urls")),
    path("mitre/", include("apps.mitre.urls")),
    path("usecases/", include("apps.usecases.urls")),
    path("sources/", include("apps.sources.urls")),
    path("access/", include("apps.access_control.urls")),
    path("sigma/", include("apps.sigma_tools.urls")),
    path("controls/", include("apps.controls.urls")),
    path("reports/", include("apps.reports.urls")),
    path("audit/", include("apps.auditlog.urls")),
    path("servers/", include("apps.server_heatmap.urls")),
    path("", root_redirect, name="home"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# El contenedor productivo también puede ejecutarse con DEBUG=0 detrás del
# reverse proxy. STATIC_ROOT contiene tanto los archivos del proyecto como los
# del admin de Django después de collectstatic.
urlpatterns += [
    re_path(
        r"^static/(?P<path>.*)$",
        serve,
        {"document_root": settings.STATIC_ROOT},
        name="local_static",
    ),
    re_path(
        r"^media/(?P<path>.*)$",
        serve,
        {"document_root": settings.MEDIA_ROOT},
        name="local_media",
    )
]
