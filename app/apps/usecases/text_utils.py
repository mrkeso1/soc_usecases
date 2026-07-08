def split_multi_value(value):
    parts = []
    seen = set()
    for raw_part in str(value or "").replace("\n", ",").replace(";", ",").split(","):
        part = " ".join(raw_part.split())
        key = part.casefold()
        if part and key not in seen:
            parts.append(part)
            seen.add(key)
    return parts


def normalize_multi_text(value):
    return ", ".join(split_multi_value(value))
