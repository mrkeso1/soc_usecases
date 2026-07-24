from apps.usecases.permissions import resolve_user_roles


def can_access_server_heatmap(user):
    roles = resolve_user_roles(user)
    if roles["is_admin"] or roles["is_analyst"]:
        return True
    if roles["is_readonly"]:
        return False
    return bool(getattr(user, "is_authenticated", False) and user.has_perm("server_heatmap.view_serverasset"))
