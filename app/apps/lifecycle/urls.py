from django.urls import path

from .views import (
    lifecycle_assign_owner,
    lifecycle_management_view,
    lifecycle_mark_done,
    lifecycle_periods_admin,
    lifecycle_reset_period,
    lifecycle_start_cycle,
)


urlpatterns = [
    path("", lifecycle_management_view, name="lifecycle_management"),
    path("periods/", lifecycle_periods_admin, name="lifecycle_periods_admin"),
    path("<int:pk>/done/", lifecycle_mark_done, name="lifecycle_mark_done"),
    path("<int:pk>/assign-owner/", lifecycle_assign_owner, name="lifecycle_assign_owner"),
    path("reset/<int:period>/", lifecycle_reset_period, name="lifecycle_reset_period"),
    path("start-cycle/", lifecycle_start_cycle, name="lifecycle_start_cycle"),
]
