ADMIN_GROUP = "Admin"
ANALYST_GROUP = "Analyst"
READONLY_GROUP = "ReadOnly"
ROLE_GROUPS = (ADMIN_GROUP, ANALYST_GROUP, READONLY_GROUP)
LEGACY_GROUPS = ("Engineer", "Reviewer")


def user_in_group(user, group_name: str) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    return user.groups.filter(name=group_name).exists()


def is_admin_role(user) -> bool:
    return bool(getattr(user, "is_superuser", False) or user_in_group(user, ADMIN_GROUP))


def is_analyst_role(user) -> bool:
    return user_in_group(user, ANALYST_GROUP)


def is_readonly_role(user) -> bool:
    return user_in_group(user, READONLY_GROUP)
