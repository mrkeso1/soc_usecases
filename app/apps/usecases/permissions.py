"""Role and ownership checks for use-case workflows."""

from apps.accounts.roles import is_admin_role, is_readonly_role

from .models import UseCase


def can_access_usecases(user) -> bool:
    """Return whether the user may access inventory/lifecycle screens."""
    return bool(
        is_admin_role(user)
        or (
            getattr(user, "is_authenticated", False)
            and not is_readonly_role(user)
            and user.has_perm("usecases.view_usecase")
        )
    )


def _user_owner_tokens(user) -> set[str]:
    values = [
        getattr(user, "username", ""),
        getattr(user, "display_name", ""),
        getattr(user, "email", ""),
    ]
    full_name = user.get_full_name() if hasattr(user, "get_full_name") else ""
    values.append(full_name)
    return {str(value).strip().casefold() for value in values if str(value).strip()}


def is_usecase_owner(user, usecase: UseCase) -> bool:
    """Match ownership through creator, control owner, or owner_name text."""
    if not getattr(user, "is_authenticated", False):
        return False
    if usecase.created_by_id == user.id or usecase.lifecycle_control_owner_id == user.id:
        return True
    owner_name = (usecase.owner_name or "").strip().casefold()
    return bool(owner_name and owner_name in _user_owner_tokens(user))


def can_add_usecases(user) -> bool:
    return bool(is_admin_role(user) or (not is_readonly_role(user) and user.has_perm("usecases.add_usecase")))


def can_manage_usecases(user, usecase: UseCase | None = None) -> bool:
    if is_admin_role(user):
        return True
    if is_readonly_role(user) or not user.has_perm("usecases.change_usecase"):
        return False
    if usecase is None:
        return True
    return is_usecase_owner(user, usecase)


def can_delete_usecases(user, usecase: UseCase | None = None) -> bool:
    if is_admin_role(user):
        return True
    if is_readonly_role(user) or not user.has_perm("usecases.delete_usecase"):
        return False
    if usecase is None:
        return True
    return is_usecase_owner(user, usecase)


def is_lifecycle_admin(user) -> bool:
    return bool(is_admin_role(user) or user.has_perm("usecases.manage_lifecycle_controls"))


def can_finish_lifecycle_review(user, usecase: UseCase) -> bool:
    return bool(
        is_lifecycle_admin(user)
        or (
            not is_readonly_role(user)
            and user.has_perm("usecases.add_lifecyclereview")
            and usecase.lifecycle_control_owner_id == user.id
        )
    )


def can_assign_lifecycle_owner(user) -> bool:
    return is_lifecycle_admin(user)
