from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect
from django.urls import include, path

from apps.usecases.views import dashboard_view


def root_redirect(request):
    return redirect("dashboard")


urlpatterns = [
    path("admin/", admin.site.urls),
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="registration/login.html"),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("usecases/", include("apps.usecases.urls")),
    path("", root_redirect, name="home"),
]