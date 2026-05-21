from apps.usecases.permissions import resolve_user_roles


def user_roles(request):
    user = getattr(request, "user", None)
    roles = resolve_user_roles(user)
    return {
        "is_role_admin": roles["is_admin"],
        "is_role_analyst": roles["is_analyst"],
        "is_role_readonly": roles["is_readonly"],
    }
