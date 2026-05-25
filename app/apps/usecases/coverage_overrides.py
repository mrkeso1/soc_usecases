"""Helpers for manual/externally-covered ATT&CK and D3FEND coverage.

The inventory keeps the real use-case mappings. CoverageOverride is a separate
layer used when a technique/tactic is covered by a tool outside of a use case,
or when an item does not apply and must be removed from coverage calculations.
"""

from dataclasses import dataclass
import unicodedata
from typing import Iterable

from .models import CoverageOverride


STATUS_ENABLED = CoverageOverride.STATUS_ENABLED
STATUS_FULFILLED = CoverageOverride.STATUS_FULFILLED
STATUS_DISABLED = CoverageOverride.STATUS_DISABLED


@dataclass(frozen=True)
class ResolvedCoverageStatus:
    status: str
    reason: str = ""
    source: str = "default"

    @property
    def is_enabled(self) -> bool:
        return self.status != STATUS_DISABLED

    @property
    def is_fulfilled(self) -> bool:
        return self.status == STATUS_FULFILLED

    @property
    def label(self) -> str:
        if self.status == STATUS_FULFILLED:
            return "Cumplida"
        if self.status == STATUS_DISABLED:
            return "Deshabilitada"
        return "Habilitada"

    @property
    def css_class(self) -> str:
        return self.status


@dataclass(frozen=True)
class CoverageOverrideUpdateResult:
    ok: bool
    message: str
    override: CoverageOverride | None = None


def split_values(raw_value: str) -> list[str]:
    return [item.strip() for item in str(raw_value or "").split(",") if item.strip()]


def override_key(framework: str, object_type: str, object_key: str) -> tuple[str, str, str]:
    return (str(framework or "").upper(), str(object_type or "").lower(), str(object_key or "").strip())


def get_override_map(framework: str, object_type: str | None = None) -> dict[tuple[str, str, str], CoverageOverride]:
    qs = CoverageOverride.objects.filter(framework=str(framework or "").upper())
    if object_type:
        qs = qs.filter(object_type=str(object_type or "").lower())
    return {
        override_key(item.framework, item.object_type, item.object_key): item
        for item in qs
    }


def resolve_status(
    override_map: dict[tuple[str, str, str], CoverageOverride],
    *,
    framework: str,
    object_type: str,
    object_key: str,
    default_enabled: bool = True,
) -> ResolvedCoverageStatus:
    item = override_map.get(override_key(framework, object_type, object_key))
    if item:
        return ResolvedCoverageStatus(item.status, item.reason, "override")
    if not default_enabled:
        return ResolvedCoverageStatus(STATUS_DISABLED, "Deshabilitada desde el catalogo", "catalog")
    return ResolvedCoverageStatus(STATUS_ENABLED, "", "default")


def update_coverage_override_from_post(post_data, user) -> CoverageOverrideUpdateResult:
    framework = post_data.get("framework", "").strip().upper()
    object_type = post_data.get("object_type", "").strip().lower()
    object_key = post_data.get("object_key", "").strip()
    object_name = post_data.get("object_name", "").strip()
    status = post_data.get("status", "").strip()
    reason = post_data.get("reason", "").strip()
    default_enabled = post_data.get("default_enabled") == "1"

    valid_frameworks = {CoverageOverride.FRAMEWORK_ATTACK, CoverageOverride.FRAMEWORK_D3FEND}
    valid_types = {CoverageOverride.OBJECT_TACTIC, CoverageOverride.OBJECT_TECHNIQUE, CoverageOverride.OBJECT_CATEGORY}
    valid_statuses = {CoverageOverride.STATUS_ENABLED, CoverageOverride.STATUS_FULFILLED, CoverageOverride.STATUS_DISABLED}

    if framework not in valid_frameworks or object_type not in valid_types or status not in valid_statuses or not object_key:
        return CoverageOverrideUpdateResult(False, "No se pudo actualizar la cobertura: datos invalidos.")

    if status in {CoverageOverride.STATUS_FULFILLED, CoverageOverride.STATUS_DISABLED} and not reason:
        return CoverageOverrideUpdateResult(False, "Indica el motivo/evidencia antes de guardar ese estado.")

    if status == CoverageOverride.STATUS_ENABLED and default_enabled:
        CoverageOverride.objects.filter(
            framework=framework,
            object_type=object_type,
            object_key=object_key,
        ).delete()
        return CoverageOverrideUpdateResult(True, "Cobertura restablecida a Habilitada.")

    override, _ = CoverageOverride.objects.update_or_create(
        framework=framework,
        object_type=object_type,
        object_key=object_key,
        defaults={
            "object_name": object_name,
            "status": status,
            "reason": reason,
            "updated_by": user,
        },
    )
    return CoverageOverrideUpdateResult(True, f"Cobertura actualizada: {override.get_status_display()}.", override)


def normalize_search_text(value: str) -> str:
    """Normalize text for forgiving admin searches.

    It removes accents and lowercases values so searches like "tecnica",
    "credential access" or "T1059" behave consistently.
    """
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.casefold()


def item_matches_query(values: Iterable[str], query: str) -> bool:
    query_text = normalize_search_text(query).strip()
    if not query_text:
        return True

    haystack = " ".join(normalize_search_text(value) for value in values)
    # All typed words must be present somewhere in the joined searchable text.
    # This makes searches more useful for inputs such as "credential access" or
    # "T1059 command" without requiring an exact contiguous substring.
    return all(term in haystack for term in query_text.split())
