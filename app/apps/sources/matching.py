import re
import unicodedata

from django.db import IntegrityError, transaction

from .models import EventSource, SourceAlias, UseCaseSource


SOURCE_SPLIT_RE = re.compile(r"[;\n]+")


def normalize_source_key(value):
    text = str(value or "").strip().casefold()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in text if not unicodedata.combining(char))
    return re.sub(r"[^a-z0-9]+", "", text)


def split_source_tokens(value):
    if not value:
        return []
    return [item.strip() for item in SOURCE_SPLIT_RE.split(str(value)) if item and item.strip()]


def resolve_event_source(token, *, create_missing=False, defaults=None):
    token = str(token or "").strip()
    if not token:
        return None, False

    defaults = defaults or {}
    code = ""
    name = token
    if " - " in token:
        maybe_code, maybe_name = token.split(" - ", 1)
        code = maybe_code.strip()
        name = maybe_name.strip() or token

    source = None
    if code:
        source = EventSource.objects.filter(code__iexact=code).first()
    if source is None:
        source = EventSource.objects.filter(name__iexact=name).first()
    if source is None:
        source = EventSource.objects.filter(host__iexact=name).first()
    if source is None:
        alias = SourceAlias.objects.select_related("source").filter(alias__iexact=token).first()
        source = alias.source if alias else None

    if source:
        _ensure_alias(source, token)
        return source, False

    if not create_missing:
        return None, False

    payload = {
        "code": code or None,
        "name": name,
        "source_type": defaults.get("source_type") or EventSource.TYPE_OTHER,
        "status": defaults.get("status") or EventSource.STATUS_ACTIVE,
        "description": defaults.get("description") or "Creada automaticamente desde inventario/importacion.",
    }
    for field_name in (
        "category_ref",
        "subcategory_ref",
        "protection",
        "delivery_method",
        "protocol",
        "port",
        "service_account",
        "host",
        "vendor",
        "product",
        "environment",
    ):
        if field_name in defaults:
            payload[field_name] = defaults[field_name]

    source = EventSource.objects.create(**payload)
    _ensure_alias(source, token)
    return source, True


def resolve_event_sources(value, *, create_missing=False, defaults=None):
    resolved = []
    created_count = 0
    unresolved = []
    for token in split_source_tokens(value):
        source, created = resolve_event_source(token, create_missing=create_missing, defaults=defaults)
        if source:
            resolved.append(source)
            created_count += int(created)
        else:
            unresolved.append(token)
    return resolved, created_count, unresolved


@transaction.atomic
def sync_usecase_sources(usecase, raw_value, *, create_missing=False, defaults=None):
    if raw_value in (None, ""):
        return {"linked": 0, "created": 0, "unresolved": []}
    sources, created_count, unresolved = resolve_event_sources(
        raw_value,
        create_missing=create_missing,
        defaults=defaults,
    )
    selected_ids = {source.id for source in sources}
    if selected_ids:
        usecase.source_links.exclude(source_id__in=selected_ids).delete()
    for source in sources:
        UseCaseSource.objects.get_or_create(
            use_case=usecase,
            source=source,
            defaults={"role": UseCaseSource.ROLE_PRIMARY, "is_required": True},
        )
    return {"linked": len(sources), "created": created_count, "unresolved": unresolved}


def _ensure_alias(source, raw_alias):
    alias = str(raw_alias or "").strip()
    if not alias:
        return
    if normalize_source_key(alias) == normalize_source_key(source.name):
        return
    try:
        SourceAlias.objects.get_or_create(source=source, alias=alias)
    except IntegrityError:
        pass
