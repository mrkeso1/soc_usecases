from apps.usecases.permissions import resolve_user_roles


def can_access_sources(user, *, _roles=None) -> bool:
    roles = _roles if _roles is not None else resolve_user_roles(user)
    if roles["is_admin"] or roles["is_analyst"]:
        return True
    if roles["is_readonly"]:
        return False
    return bool(getattr(user, "is_authenticated", False) and user.has_perm("sources.view_eventsource"))


def can_manage_sources(user, *, _roles=None) -> bool:
    roles = _roles if _roles is not None else resolve_user_roles(user)
    if roles["is_admin"] or roles["is_analyst"]:
        return True
    if roles["is_readonly"]:
        return False
    return bool(getattr(user, "is_authenticated", False) and user.has_perm("sources.change_eventsource"))

