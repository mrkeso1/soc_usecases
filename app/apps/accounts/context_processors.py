from .roles import is_admin_role, is_analyst_role, is_readonly_role


def user_roles(request):
    user = getattr(request, "user", None)
    return {
        "is_role_admin": is_admin_role(user),
        "is_role_analyst": is_analyst_role(user),
        "is_role_readonly": is_readonly_role(user),
    }
