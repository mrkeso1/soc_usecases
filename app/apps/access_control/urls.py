from django.urls import path

from .views import (
    access_control_home,
    access_role_create,
    access_role_edit,
    admin_console,
)


urlpatterns = [
    path("", access_control_home, name="access_control_home"),
    path("admin/", admin_console, name="admin_console"),
    path("roles/new/", access_role_create, name="access_role_create"),
    path("roles/<int:pk>/edit/", access_role_edit, name="access_role_edit"),
]
