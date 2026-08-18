import fnmatch
import re
from dataclasses import dataclass

from django.db import transaction

from .models import InventoryFilterDecision, InventoryFilterRule, InventorySyncRun, ServerAsset


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
    if source == InventorySyncRun.SOURCE_LEGACY:
        source = InventorySyncRun.SOURCE_AD
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
    ad_run = InventorySyncRun.objects.filter(
        source=InventorySyncRun.SOURCE_AD,
        status=InventorySyncRun.STATUS_SUCCESS,
    ).first()
    if not ad_run:
        ad_run = InventorySyncRun.objects.filter(
            source=InventorySyncRun.SOURCE_LEGACY,
            status=InventorySyncRun.STATUS_SUCCESS,
        ).first()
    if ad_run:
        runs.append(ad_run)
    for source in (InventorySyncRun.SOURCE_SIEM,):
        run = InventorySyncRun.objects.filter(
            source=source,
            status=InventorySyncRun.STATUS_SUCCESS,
        ).first()
        if run:
            runs.append(run)
    return runs


def apply_inventory_filters():
    """Aplica reglas activas a las últimas cargas y actualiza los cálculos base."""
    compiled = load_compiled_filters()
    runs = latest_inventory_runs()
    ad_asset_ids = set()
    siem_asset_ids = set()
    excluded_asset_ids = set()
    classification_by_asset = {}
    decisions = []
    processed = 0
    excluded = 0
    has_ad_run = any(
        run.source in (InventorySyncRun.SOURCE_AD, InventorySyncRun.SOURCE_LEGACY)
        for run in runs
    )
    has_siem_run = any(run.source == InventorySyncRun.SOURCE_SIEM for run in runs)

    for run in runs:
        source = InventorySyncRun.SOURCE_AD if run.source == InventorySyncRun.SOURCE_LEGACY else run.source
        for observation in run.observations.select_related("asset").order_by("id").iterator(chunk_size=1000):
            processed += 1
            evaluation = evaluate_observation(observation, compiled)
            identifier = (
                observation.hostname
                or observation.fqdn
                or str(observation.ip_address or "")
                or observation.external_id
            )
            for rule in evaluation["matched_rules"]:
                decisions.append(
                    InventoryFilterDecision(
                        sync_run=run,
                        rule=rule,
                        source=source,
                        identifier=identifier,
                        action=rule.action,
                        reason=rule.reason,
                        raw_data={"observation_id": observation.id},
                    )
                )
            if evaluation["excluded"]:
                excluded += 1
                if observation.asset_id:
                    excluded_asset_ids.add(observation.asset_id)
                continue
            asset = observation.asset
            if not asset:
                continue
            if source == InventorySyncRun.SOURCE_AD:
                ad_asset_ids.add(asset.id)
            elif source == InventorySyncRun.SOURCE_SIEM:
                siem_asset_ids.add(asset.id)

            if asset.classification_source == ServerAsset.CLASSIFICATION_MANUAL:
                continue
            assignments = classification_by_asset.setdefault(asset.id, {})
            for rule in evaluation["classification_rules"]:
                if rule.category_id and "category_id" not in assignments:
                    assignments["category_id"] = rule.category_id
                if rule.os_family and "os_family" not in assignments:
                    assignments["os_family"] = rule.os_family
                if rule.environment_value and "environment" not in assignments:
                    assignments["environment"] = rule.environment_value
                if rule.server_type_value and "server_type" not in assignments:
                    assignments["server_type"] = rule.server_type_value

    with transaction.atomic():
        ServerAsset.objects.update(is_excluded_by_rule=False)
        if excluded_asset_ids:
            ServerAsset.objects.filter(id__in=excluded_asset_ids).update(
                is_excluded_by_rule=True,
            )
        if has_ad_run:
            ServerAsset.objects.update(in_active_directory=False)
            if ad_asset_ids:
                ServerAsset.objects.filter(id__in=ad_asset_ids).update(in_active_directory=True)
        if has_siem_run:
            ServerAsset.objects.update(in_siem=False)
            if siem_asset_ids:
                ServerAsset.objects.filter(id__in=siem_asset_ids).update(in_siem=True)
        for asset_id, assignments in classification_by_asset.items():
            ServerAsset.objects.filter(
                id=asset_id,
                classification_source=ServerAsset.CLASSIFICATION_AUTO,
            ).update(**assignments)
        InventoryFilterDecision.objects.filter(sync_run__in=runs).delete()
        InventoryFilterDecision.objects.bulk_create(decisions, batch_size=1000)

    return {
        "processed": processed,
        "excluded": excluded,
        "excluded_assets": len(excluded_asset_ids),
        "classified": len(classification_by_asset),
        "decisions": len(decisions),
        "runs": len(runs),
    }


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
        "run_rows": [],
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
        run_row = {
            "source": (
                "Active Directory (carga importada)"
                if run.source == InventorySyncRun.SOURCE_LEGACY
                else run.get_source_display()
            ),
            "received": 0,
            "matched": 0,
        }
        result["run_rows"].append(run_row)
        observations = run.observations.all().order_by("id")
        for observation in observations.iterator(chunk_size=500):
            result["received"] += 1
            run_row["received"] += 1
            evaluation = evaluate_observation(observation, compiled)
            matched_rules = evaluation["matched_rules"]
            if matched_rules:
                result["matched"] += 1
                run_row["matched"] += 1
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
