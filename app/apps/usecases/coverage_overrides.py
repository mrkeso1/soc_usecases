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
        return ResolvedCoverageStatus(STATUS_DISABLED, "Deshabilitada desde el catálogo", "catalog")
    return ResolvedCoverageStatus(STATUS_ENABLED, "", "default")


def normalize_search_text(value: str) -> str:
    """Normalize text for forgiving admin searches.

    It removes accents and lowercases values so searches like "tecnica",
    "técnica", "credential access" or "T1059" behave consistently.
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
