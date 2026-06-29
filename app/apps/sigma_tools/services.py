import re
import uuid
from datetime import datetime

import yaml

from .models import UseCaseTechnicalBackup


def _compact_epl(epl):
    return "\n".join(
        line.strip()
        for line in epl.splitlines()
        if line.strip() and not line.strip().startswith("--")
    )


def _find_matching_parenthesis(text, open_index):
    depth = 0
    quote = None
    escape = False
    for index in range(open_index, len(text)):
        char = text[index]
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _event_source_and_expression(epl):
    compact = _compact_epl(epl)
    flat = " ".join(compact.split())
    event_match = re.search(r"\bfrom\s+([A-Za-z0-9_.]+)\s*\(", compact, re.I)
    if event_match:
        open_index = compact.find("(", event_match.end() - 1)
        close_index = _find_matching_parenthesis(compact, open_index)
        if close_index > open_index:
            return event_match.group(1), compact[open_index + 1:close_index]
    source_match = re.search(r"\bfrom\s+([A-Za-z0-9_.]+)", flat, re.I)
    where_match = re.search(r"\bwhere\b\s+(.+?)(?=\bgroup\s+by\b|\bhaving\b|$)", flat, re.I)
    return source_match.group(1) if source_match else "Event", where_match.group(1) if where_match else ""


def _split_top_level(expression, operator):
    parts = []
    depth = 0
    quote = None
    token_start = 0
    index = 0
    pattern = re.compile(rf"\b{operator}\b", re.I)
    while index < len(expression):
        char = expression[index]
        if quote:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            index += 1
            continue
        if char in "({":
            depth += 1
            index += 1
            continue
        if char in ")}":
            depth = max(0, depth - 1)
            index += 1
            continue
        match = pattern.match(expression, index)
        if depth == 0 and match:
            parts.append(expression[token_start:index].strip())
            token_start = match.end()
            index = match.end()
            continue
        index += 1
    parts.append(expression[token_start:].strip())
    return [part for part in parts if part]


def _strip_outer_parentheses(value):
    value = value.strip().rstrip(";").strip()
    while value.startswith("(") and value.endswith(")"):
        close_index = _find_matching_parenthesis(value, 0)
        if close_index != len(value) - 1:
            break
        value = value[1:-1].strip()
    return value


def _clean_field(field):
    field = field.strip().strip("`")
    field = re.sub(r"\.firstOf\(\)", "", field, flags=re.I)
    field = re.sub(r"\.toString\(\)", "", field, flags=re.I)
    field = re.sub(r"\.toLowerCase\(\)", "", field, flags=re.I)
    field = field.strip().strip("`")
    return field


def _parse_epl_values(raw_values):
    return [
        item.strip().strip("'\"")
        for item in raw_values.split(",")
        if item.strip().strip("'\"")
    ]


def _add_condition(selection, key, value):
    if key in selection:
        current = selection[key]
        current_values = current if isinstance(current, list) else [current]
        new_values = value if isinstance(value, list) else [value]
        selection[key] = current_values + [item for item in new_values if item not in current_values]
        return
    selection[key] = value


def _parse_simple_condition(condition):
    condition = _strip_outer_parentheses(condition)
    if not condition:
        return {}

    is_one_of = re.match(
        r"isOneOfIgnoreCase\s*\(\s*(`?[\w.]+`?)\s*,\s*\{\s*(.*?)\s*\}\s*\)\s*$",
        condition,
        re.I | re.S,
    )
    if is_one_of:
        return {_clean_field(is_one_of.group(1)): _parse_epl_values(is_one_of.group(2))}

    not_null = re.match(r"(`?[\w.]+`?(?:\.\w+\(\))*)\s+IS\s+NOT\s+NULL\s*$", condition, re.I)
    if not_null:
        return {f"{_clean_field(not_null.group(1))}|exists": True}

    null_match = re.match(r"(`?[\w.]+`?(?:\.\w+\(\))*)\s+IS\s+NULL\s*$", condition, re.I)
    if null_match:
        return {f"{_clean_field(null_match.group(1))}|exists": False}

    comparison = re.match(
        r"(`?[\w.]+`?(?:\.\w+\(\))*)\s*(=|!=|like|regexp)\s*['\"]([^'\"]+)['\"]\s*$",
        condition,
        re.I,
    )
    if comparison:
        field, operator, value = _clean_field(comparison.group(1)), comparison.group(2).lower(), comparison.group(3)
        if operator == "like":
            clean_value = value.strip("%")
            modifier = "|contains" if value.startswith("%") or value.endswith("%") else ""
            return {f"{field}{modifier}": clean_value}
        if operator == "regexp":
            return {f"{field}|re": value}
        if operator == "!=":
            return {field: {"not": value}}
        return {field: value}

    return {}


def _parse_detection(expression):
    base_selection = {}
    or_selections = []
    for part in _split_top_level(expression, "AND"):
        part = _strip_outer_parentheses(part)
        or_parts = _split_top_level(part, "OR")
        if len(or_parts) > 1:
            group = []
            for or_part in or_parts:
                parsed = _parse_simple_condition(or_part)
                if parsed:
                    group.append(parsed)
            if group:
                or_selections.append(group)
            continue
        parsed = _parse_simple_condition(part)
        for key, value in parsed.items():
            _add_condition(base_selection, key, value)

    detection = {}
    condition_parts = []
    if base_selection:
        detection["selection"] = base_selection
        condition_parts.append("selection")
    for group_index, group in enumerate(or_selections, 1):
        group_names = []
        for item_index, selection in enumerate(group, 1):
            name = f"selection_or_{group_index}_{item_index}"
            detection[name] = selection
            group_names.append(name)
        if group_names:
            condition_parts.append("(" + " or ".join(group_names) + ")")
    if not detection:
        detection["selection"] = {}
        condition_parts.append("selection")
    detection["condition"] = " and ".join(condition_parts)
    return detection


def epl_to_sigma(epl):
    statement = " ".join(_compact_epl(epl).split())
    source, expression = _event_source_and_expression(epl)
    name_match = re.search(r"@Name\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", epl, re.I)
    description_match = re.search(r"@Description\s*\(\s*['\"]([^'\"]*)['\"]\s*\)", epl, re.I)
    group_match = re.search(r"\bgroup\s+by\b\s+(.+?)(?=\bhaving\b|$)", statement, re.I)
    having_match = re.search(r"\bhaving\b\s+(.+)$", statement, re.I)
    rule = {
        "title": name_match.group(1) if name_match else f"Deteccion convertida desde EPL - {source}",
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": description_match.group(1) or "Regla migrada desde ESA EPL Advanced." if description_match else "Regla migrada desde ESA EPL Advanced.",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "logsource": {"product": source.lower()},
        "detection": _parse_detection(expression) if expression else {"selection": {"event_type": source}, "condition": "selection"},
        "falsepositives": ["Revisar en el entorno"],
        "level": "medium",
    }
    if group_match or having_match:
        rule["correlation"] = {
            "type": "event_count",
            "group-by": [
                item.strip()
                for item in (group_match.group(1) if group_match else "").split(",")
                if item.strip()
            ],
            "condition": having_match.group(1).strip() if having_match else "count() >= 1",
        }
    return yaml.safe_dump(rule, allow_unicode=True, sort_keys=False)


def sigma_to_rule(sigma_text, target):
    rule = yaml.safe_load(sigma_text) or {}
    detection = rule.get("detection", {})
    selections = [
        value
        for key, value in detection.items()
        if key != "condition" and isinstance(value, dict)
    ]
    expressions = []
    for selection in selections:
        for field, value in selection.items():
            clean_field = field.split("|", 1)[0]
            values = value if isinstance(value, list) else [value]
            expressions.append("(" + " OR ".join(f'{clean_field} = "{item}"' for item in values) + ")")
    condition = " AND ".join(expressions) or "true"
    name = rule.get("title", "Sigma Detection")
    target = target.lower()
    if target == "netwitness":
        return f'@Name("{name}")\nSELECT * FROM Event(\n  {condition}\n).win:time_batch(5 minutes);'
    if target == "splunk":
        return f'{condition.replace(" = ", "=")} | stats count by host | where count >= 1'
    if target == "sentinel":
        return f'SecurityEvent\n| where {condition.replace("=", "==")}\n| summarize count() by Computer'
    if target == "elastic":
        return f'rule.name: "{name}"\nrule.language: "kuery"\nrule.query: \'{condition}\''
    if target == "qradar":
        return f"SELECT * FROM events WHERE {condition} LAST 5 MINUTES"
    return f"# {name}\n{condition}"


def rule_condition_summary(usecase):
    lines = []
    for condition in usecase.rule_conditions.all().order_by("position", "id"):
        value = f" {condition.value}" if condition.value else ""
        lines.append(
            f"{condition.position}. {condition.get_condition_type_display()}: "
            f"{condition.field_name} {condition.get_operator_display()}{value}"
        )
    return "\n".join(lines)


def build_inventory_rule_backup_payload(usecase):
    logic_text = (usecase.full_rule_text or "").strip()
    if not logic_text:
        logic_text = rule_condition_summary(usecase).strip()

    notes = "Generado automaticamente desde la regla cargada en el inventario."
    if usecase.functional_description:
        notes = f"{notes}\n\nDescripcion funcional:\n{usecase.functional_description.strip()}"

    return {
        "backup_type": UseCaseTechnicalBackup.TYPE_LOGIC,
        "title": "Backup desde regla de inventario",
        "logic_text": logic_text,
        "sigma_text": "",
        "notes": notes,
    }


def sync_inventory_rule_backup(usecase, user=None):
    payload = build_inventory_rule_backup_payload(usecase)
    logic_text = payload["logic_text"].strip()
    if not logic_text:
        return None, False

    current = UseCaseTechnicalBackup.current_for_usecase(usecase)
    if current and (current.logic_text or "").strip() == logic_text:
        return current, False

    backup = UseCaseTechnicalBackup.objects.create(
        use_case=usecase,
        created_by=user if getattr(user, "is_authenticated", False) else None,
        **payload,
    )
    return backup, True
