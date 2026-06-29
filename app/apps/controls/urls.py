from django.urls import path

from .views import control_create, control_delete, control_detail, control_edit, control_history, control_list


urlpatterns = [
    path("", control_list, name="control_list"),
    path("new/", control_create, name="control_create"),
    path("history/", control_history, name="control_history"),
    path("<int:pk>/", control_detail, name="control_detail"),
    path("<int:pk>/edit/", control_edit, name="control_edit"),
    path("<int:pk>/delete/", control_delete, name="control_delete"),
]
