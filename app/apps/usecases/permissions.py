"""Role and ownership checks for use-case workflows."""

import re
import unicodedata

from .models import UseCase


def resolve_user_roles(user) -> dict:
    """Resolve role/group flags in one place and one DB query."""
    if not getattr(user, "is_authenticated", False):
        return {"groups": set(), "is_admin": False, "is_analyst": False, "is_readonly": False}

    group_names = set(user.groups.values_list("name", flat=True))
    is_admin = bool(getattr(user, "is_superuser", False) or "Admin" in group_names)
    is_analyst = "Analyst" in group_names
    is_readonly = "ReadOnly" in group_names and not is_admin and not is_analyst
    return {
        "groups": group_names,
        "is_admin": is_admin,
        "is_analyst": is_analyst,
        "is_readonly": is_readonly,
    }


def _roles_from_user(user, _roles: dict | None) -> dict:
    """Return a resolved roles dict, computing it from the user if not supplied."""
    return _roles if _roles is not None else resolve_user_roles(user)


def can_access_usecases(user, *, _roles: dict | None = None) -> bool:
    r = _roles_from_user(user, _roles)
    if r["is_admin"] or r["is_analyst"]:
        return True
    if r["is_readonly"]:
        return False
    return bool(
        getattr(user, "is_authenticated", False)
        and user.has_perm("usecases.view_usecase")
    )


def _normalize_owner_value(value: str) -> str:
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    value = re.sub(r"[^a-zA-Z0-9@._+-]+", " ", value).strip().casefold()
    return re.sub(r"\s+", " ", value)


def _user_owner_tokens(user) -> set[str]:
    values = [
        getattr(user, "username", ""),
        getattr(user, "display_name", ""),
        getattr(user, "email", ""),
        getattr(user, "first_name", ""),
        getattr(user, "last_name", ""),
    ]
    full_name = user.get_full_name() if hasattr(user, "get_full_name") else ""
    values.append(full_name)
    tokens = {_normalize_owner_value(v) for v in values if str(v).strip()}
    email = getattr(user, "email", "") or ""
    if "@" in email:
        tokens.add(_normalize_owner_value(email.split("@", 1)[0]))
    return {t for t in tokens if t}


def is_usecase_owner(user, usecase: UseCase) -> bool:
    """Match ownership through creator, control owner, or owner_name text."""
    if not getattr(user, "is_authenticated", False):
        return False
    if usecase.created_by_id == user.id or usecase.lifecycle_control_owner_id == user.id:
        return True
    owner_name = _normalize_owner_value(usecase.owner_name)
    if not owner_name:
        return False
    for token in _user_owner_tokens(user):
        if token == owner_name:
            return True
    return False


def can_add_usecases(user, *, _roles: dict | None = None) -> bool:
    r = _roles_from_user(user, _roles)
    if r["is_admin"] or r["is_analyst"]:
        return True
    if r["is_readonly"]:
        return False
    return bool(user.has_perm("usecases.add_usecase"))


def can_manage_usecases(user, usecase: UseCase | None = None, *, _roles: dict | None = None) -> bool:
    r = _roles_from_user(user, _roles)
    if r["is_admin"]:
        return True
    if r["is_readonly"]:
        return False
    if not (r["is_analyst"] or user.has_perm("usecases.change_usecase")):
        return False
    if usecase is None:
        return True
    return is_usecase_owner(user, usecase)


def can_delete_usecases(user, usecase: UseCase | None = None, *, _roles: dict | None = None) -> bool:
    r = _roles_from_user(user, _roles)
    if r["is_admin"]:
        return True
    if r["is_readonly"] or not user.has_perm("usecases.delete_usecase"):
        return False
    if usecase is None:
        return True
    return is_usecase_owner(user, usecase)


def is_lifecycle_admin(user, *, _roles: dict | None = None) -> bool:
    r = _roles_from_user(user, _roles)
    if r["is_admin"]:
        return True
    return bool(user.has_perm("usecases.manage_lifecycle_controls"))


def can_finish_lifecycle_review(user, usecase: UseCase | None, *, _roles: dict | None = None) -> bool:
    r = _roles_from_user(user, _roles)
    if is_lifecycle_admin(user, _roles=r):
        return True
    if r["is_readonly"]:
        return False
    if not (r["is_analyst"] or user.has_perm("usecases.add_lifecyclereview")):
        return False
    if usecase is None:
        return False
    return usecase.lifecycle_control_owner_id == user.id


def can_assign_lifecycle_owner(user, *, _roles: dict | None = None) -> bool:
    return is_lifecycle_admin(user, _roles=_roles)
