from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("Información adicional", {"fields": ("display_name", "ldap_dn", "area")}),
    )
    list_display = ("username", "email", "display_name", "is_staff", "is_active")