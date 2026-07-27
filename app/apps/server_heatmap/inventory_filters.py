import fnmatch
import re
from dataclasses import dataclass

from .models import InventoryFilterRule, InventorySyncRun


@dataclass(frozen=True)
class CompiledInventoryFilter:
    rule: InventoryFilterRule
    regex: re.Pattern | None = None

    def matches(self, value):
        candidate = str(value or "").strip()
        pattern = self.rule.pattern.strip()
        if not candidate or not pattern:
            return False
        candidate_folded = candidate.casefold()
        pattern_folded = pattern.casefold()
        if self.rule.operator == InventoryFilterRule.OP_EXACT:
            return candidate_folded == pattern_folded
        if self.rule.operator == InventoryFilterRule.OP_CONTAINS:
            return pattern_folded in candidate_folded
        if self.rule.operator == InventoryFilterRule.OP_WILDCARD:
            return fnmatch.fnmatchcase(candidate_folded, pattern_folded)
        return bool(self.regex and self.regex.search(candidate))


def compile_inventory_filter(rule):
    regex = None
    if rule.operator == InventoryFilterRule.OP_REGEX:
        regex = re.compile(rule.pattern, flags=re.IGNORECASE)
    elif rule.operator == InventoryFilterRule.OP_WORD:
        regex = re.compile(
            rf"(?<!\w){re.escape(rule.pattern.strip())}(?!\w)",
            flags=re.IGNORECASE,
        )
    return CompiledInventoryFilter(rule=rule, regex=regex)


def load_compiled_filters(*, active_only=True, rules=None):
    queryset = rules if rules is not None else InventoryFilterRule.objects.all()
    if active_only:
        queryset = queryset.filter(is_active=True)
    queryset = queryset.select_related("category").order_by("priority", "name")
    return [compile_inventory_filter(rule) for rule in queryset]


def rule_applies_to_source(rule, source):
    return rule.source in (InventoryFilterRule.SOURCE_BOTH, source)


def observation_value(observation, field):
    return getattr(observation, field, "")


def evaluate_observation(observation, compiled_filters):
    matched = []
    scope_decision = None
    classifications = []
    for compiled in compiled_filters:
        rule = compiled.rule
        if not rule_applies_to_source(rule, observation.source):
            continue
        if not compiled.matches(observation_value(observation, rule.field)):
            continue
        matched.append(rule)
        if rule.action in (
            InventoryFilterRule.ACTION_INCLUDE,
            InventoryFilterRule.ACTION_EXCLUDE,
        ):
            if scope_decision is None:
                scope_decision = rule
        elif rule.action == InventoryFilterRule.ACTION_CLASSIFY:
            classifications.append(rule)
    return {
        "matched_rules": matched,
        "scope_decision": scope_decision,
        "classification_rules": classifications,
        "excluded": bool(
            scope_decision
            and scope_decision.action == InventoryFilterRule.ACTION_EXCLUDE
        ),
    }


def latest_inventory_runs():
    runs = []
    for source in (InventorySyncRun.SOURCE_AD, InventorySyncRun.SOURCE_SIEM):
        run = InventorySyncRun.objects.filter(
            source=source,
            status=InventorySyncRun.STATUS_SUCCESS,
        ).first()
        if run:
            runs.append(run)
    return runs


def simulate_inventory_filters(*, rules=None, sample_limit=20):
    compiled = load_compiled_filters(
        active_only=rules is None,
        rules=rules,
    )
    statistics = {
        item.rule.id: {
            "rule": item.rule,
            "matches": 0,
            "effective": 0,
            "samples": [],
        }
        for item in compiled
    }
    result = {
        "runs": [],
        "received": 0,
        "matched": 0,
        "excluded": 0,
        "included_by_rule": 0,
        "classified": 0,
        "unmatched": 0,
        "rules": statistics,
    }
    for run in latest_inventory_runs():
        result["runs"].append(run)
        observations = run.observations.all().order_by("id")
        for observation in observations.iterator(chunk_size=500):
            result["received"] += 1
            evaluation = evaluate_observation(observation, compiled)
            matched_rules = evaluation["matched_rules"]
            if matched_rules:
                result["matched"] += 1
            else:
                result["unmatched"] += 1
            for rule in matched_rules:
                row = statistics[rule.id]
                row["matches"] += 1
                if len(row["samples"]) < sample_limit:
                    row["samples"].append(
                        observation.hostname
                        or observation.fqdn
                        or str(observation.ip_address or "")
                        or observation.external_id
                    )
            scope = evaluation["scope_decision"]
            if scope:
                statistics[scope.id]["effective"] += 1
                if scope.action == InventoryFilterRule.ACTION_EXCLUDE:
                    result["excluded"] += 1
                else:
                    result["included_by_rule"] += 1
            if evaluation["classification_rules"] and not evaluation["excluded"]:
                result["classified"] += 1
                for rule in evaluation["classification_rules"]:
                    statistics[rule.id]["effective"] += 1
    result["rule_rows"] = list(statistics.values())
    return result
