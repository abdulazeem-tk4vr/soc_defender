from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .observation import ParsedObservation
from .verifier import gate_containment

if TYPE_CHECKING:
    from .policy import DefenderPolicy


STEP_COST = 0.1
ATTRIBUTION_FIELD_GAIN = 1.5
CONTAINMENT_GAIN = 1.0

REPORT_FIELDS = ("patient_zero_host", "compromised_user", "attacker_domain", "data_target")

FIELD_ENTITY_TYPE = {
    "patient_zero_host": "host",
    "compromised_user": "user",
    "attacker_domain": "domain",
    "data_target": "target",
}

FIELD_SOURCE_TABLES = {
    "patient_zero_host": ("auth_logs", "netflow", "process_events", "alerts"),
    "compromised_user": ("auth_logs", "process_events", "alerts"),
    "attacker_domain": ("alerts", "netflow"),
    "data_target": ("process_events",),
}

CONTAINMENT_CANDIDATES = (
    ("block_domain", "attacker_domain", "blocked_domains"),
    ("isolate_host", "patient_zero_host", "isolated_hosts"),
    ("reset_user", "compromised_user", "reset_users"),
)


@dataclass(frozen=True)
class ReportDecision:
    submit: bool
    reason: str
    best_next_gain: float


def report_decision(policy: DefenderPolicy, parsed: ParsedObservation) -> ReportDecision:
    if parsed.step_index >= policy._report_deadline_step():
        return ReportDecision(True, "report deadline reached", 0.0)

    containment_gain = pending_containment_gain(policy, parsed)
    if containment_gain > STEP_COST:
        return ReportDecision(False, "verified containment remains valuable", containment_gain)

    investigation_gain = investigation_gain_estimate(policy, parsed)
    if investigation_gain <= STEP_COST:
        return ReportDecision(True, "remaining investigation is not worth another environment step", investigation_gain)
    return ReportDecision(False, "more evidence can still improve oracle score", investigation_gain)


def report_gaps(policy: DefenderPolicy) -> set[str]:
    return {
        field
        for field in REPORT_FIELDS
        if policy.report_tracker.values.get(field) in (None, "unknown")
    }


def pending_containment_gain(policy: DefenderPolicy, parsed: ParsedObservation) -> float:
    gains = []
    for action_type, report_field, containment_field in CONTAINMENT_CANDIDATES:
        entity_value = policy.report_tracker.values.get(report_field)
        if not entity_value or entity_value == "unknown":
            continue
        if entity_value in set(parsed.containment.get(containment_field) or []):
            continue
        if (action_type, entity_value) in policy.attempted_containment:
            continue
        decision = gate_containment(
            action_type,
            entity_value,
            policy.registry,
            step_index=parsed.step_index,
            containment_min_step=policy.containment_min_step,
        )
        if decision.approved:
            gains.append(CONTAINMENT_GAIN)
            continue
        if parsed.step_index < policy.containment_min_step and policy.registry.support_for(entity_value):
            gains.append(CONTAINMENT_GAIN)
    return max(gains, default=0.0)


def investigation_gain_estimate(policy: DefenderPolicy, parsed: ParsedObservation) -> float:
    gaps = report_gaps(policy)
    if not gaps:
        return 0.0

    if parsed.new_alerts or parsed.new_emails:
        return ATTRIBUTION_FIELD_GAIN

    gains = []
    tried_tables = _tried_tables(policy)
    for field in gaps:
        entity_type = FIELD_ENTITY_TYPE[field]
        if policy.registry.best_entities(entity_type):
            gains.append(ATTRIBUTION_FIELD_GAIN)
            continue
        untried_sources = [
            source
            for source in FIELD_SOURCE_TABLES[field]
            if source not in tried_tables
        ]
        if untried_sources:
            gains.append(ATTRIBUTION_FIELD_GAIN)
    return max(gains, default=0.0)


def _tried_tables(policy: DefenderPolicy) -> set[str]:
    return {
        str(item.get("log_type"))
        for item in policy.sql_planner.query_history
        if item.get("log_type")
    }
