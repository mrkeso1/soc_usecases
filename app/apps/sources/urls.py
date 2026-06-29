from django.urls import path

from .views import (
    source_admin_catalog,
    source_category_create,
    source_category_delete,
    source_category_edit,
    source_create,
    source_delete,
    source_detail,
    source_delivery_method_create,
    source_delivery_method_delete,
    source_delivery_method_edit,
    source_edit,
    source_list,
    source_subcategory_create,
    source_type_create,
    source_type_delete,
    source_type_edit,
    usecase_source_create,
    usecase_source_delete,
)


urlpatterns = [
    path("", source_list, name="source_list"),
    path("new/", source_create, name="source_create"),
    path("admin/catalog/", source_admin_catalog, name="source_admin_catalog"),
    path("admin/categories/new/", source_category_create, name="source_category_create"),
    path("admin/subcategories/new/", source_subcategory_create, name="source_subcategory_create"),
    path("admin/categories/<int:pk>/edit/", source_category_edit, name="source_category_edit"),
    path("admin/categories/<int:pk>/delete/", source_category_delete, name="source_category_delete"),
    path("admin/types/new/", source_type_create, name="source_type_create"),
    path("admin/types/<int:pk>/edit/", source_type_edit, name="source_type_edit"),
    path("admin/types/<int:pk>/delete/", source_type_delete, name="source_type_delete"),
    path("admin/delivery-methods/new/", source_delivery_method_create, name="source_delivery_method_create"),
    path("admin/delivery-methods/<int:pk>/edit/", source_delivery_method_edit, name="source_delivery_method_edit"),
    path("admin/delivery-methods/<int:pk>/delete/", source_delivery_method_delete, name="source_delivery_method_delete"),
    path("links/new/", usecase_source_create, name="usecase_source_create"),
    path("links/<int:pk>/delete/", usecase_source_delete, name="usecase_source_delete"),
    path("<int:pk>/", source_detail, name="source_detail"),
    path("<int:pk>/edit/", source_edit, name="source_edit"),
    path("<int:pk>/delete/", source_delete, name="source_delete"),
]
