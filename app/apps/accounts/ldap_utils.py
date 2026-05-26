from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn


SENSITIVE_MARKERS = ("password", "passwd", "secret", "token", "credential")


def escape_ldap_filter_value(value: str) -> str:
    return escape_filter_chars(str(value or ""))


def escape_ldap_dn_value(value: str) -> str:
    return escape_rdn(str(value or ""))


def safe_ldap_error_message(exc: Exception, default: str = "Error LDAP.") -> str:
    text = str(exc or "").strip()
    if not text:
        return default
    lowered = text.lower()
    if any(marker in lowered for marker in SENSITIVE_MARKERS):
        return default
    return text[:500]
