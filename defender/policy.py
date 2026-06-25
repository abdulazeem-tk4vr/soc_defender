from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .actions import block_domain, fetch_alert, fetch_email, isolate_host, reset_user, submit_report
from .evidence_registry import EvidenceRegistry
from .observation import ParsedObservation, parse_observation
from .report_readiness import ReportReadinessTracker
from .sql_planner import SQLPlanner
from .verifier import gate_containment


@dataclass
class DefenderPolicy:
    mode: str = "evidence_gate_only"
    max_steps: int = 15
    containment_min_step: int = 5
    report_deadline_step: int | None = None
    registry: EvidenceRegistry = field(default_factory=EvidenceRegistry)
    report_tracker: ReportReadinessTracker = field(default_factory=ReportReadinessTracker)
    sql_planner: SQLPlanner = field(default_factory=SQLPlanner)
    fetched_emails: set[str] = field(default_factory=set)
    fetched_alerts: set[str] = field(default_factory=set)
    attempted_containment: set[tuple[str, str]] = field(default_factory=set)
    current_scenario_id: str | None = None

    def next_action(self, observation: dict[str, Any]):
        parsed = parse_observation(observation)
        self.ingest_observation(parsed)

        if self.should_submit_deadline_report(parsed):
            return submit_report(self.build_report(parsed.containment))

        action = self.next_unseen_fetch(parsed)
        if action is not None:
            return action

        if self.containment_window_open(parsed.step_index):
            containment = self.next_gated_containment(parsed.step_index, parsed.containment)
            if containment is not None:
                return containment

        if self.should_submit_complete_report(parsed):
            return submit_report(self.build_report(parsed.containment))

        return self.investigate(parsed)

    def ingest_observation(self, observation: ParsedObservation | dict[str, Any]) -> dict[str, Any]:
        parsed = observation if isinstance(observation, ParsedObservation) else parse_observation(observation)
        self.ensure_scenario(parsed)
        supports_before = len(self.registry.supports)
        self.registry.update_from_observation(parsed)
        self.report_tracker.update(self.registry)
        self.record_failed_query(parsed)
        return {
            "supports_before_action": supports_before,
            "supports_after_update": len(self.registry.supports),
            "report_values": dict(self.report_tracker.values),
        }

    def ensure_scenario(self, observation: ParsedObservation | dict[str, Any]) -> bool:
        parsed = observation if isinstance(observation, ParsedObservation) else parse_observation(observation)
        scenario_id = parsed.scenario_id
        if not scenario_id:
            return False
        if self.current_scenario_id is None:
            self.current_scenario_id = scenario_id
            return False
        if scenario_id == self.current_scenario_id:
            return False
        self.reset_episode_state(scenario_id)
        return True

    def reset_episode_state(self, scenario_id: str | None = None) -> None:
        self.registry = EvidenceRegistry()
        self.report_tracker = ReportReadinessTracker()
        self.sql_planner = SQLPlanner()
        self.fetched_emails.clear()
        self.fetched_alerts.clear()
        self.attempted_containment.clear()
        self.current_scenario_id = scenario_id

    def next_unseen_fetch(self, parsed):
        for alert_id in parsed.new_alerts:
            if alert_id not in self.fetched_alerts:
                self.fetched_alerts.add(alert_id)
                return fetch_alert(alert_id)
        for email_id in parsed.new_emails:
            if email_id not in self.fetched_emails:
                self.fetched_emails.add(email_id)
                return fetch_email(email_id)
        return None

    def next_gated_containment(self, step_index: int, containment: dict[str, list[str]]):
        candidates = [
            (
                "block_domain",
                "domain",
                block_domain,
                self.report_tracker.values.get("attacker_domain"),
                set(containment.get("blocked_domains") or []),
            ),
            (
                "isolate_host",
                "host",
                isolate_host,
                self.report_tracker.values.get("patient_zero_host"),
                set(containment.get("isolated_hosts") or []),
            ),
            (
                "reset_user",
                "user",
                reset_user,
                self.report_tracker.values.get("compromised_user"),
                set(containment.get("reset_users") or []),
            ),
        ]
        for action_type, entity_type, builder, entity_value, already_done in candidates:
            if not entity_value or entity_value == "unknown":
                continue
            key = (action_type, entity_value)
            if entity_value in already_done or key in self.attempted_containment:
                continue
            decision = gate_containment(
                action_type,
                entity_value,
                self.registry,
                step_index=step_index,
                containment_min_step=self.containment_min_step,
            )
            if decision.approved:
                self.attempted_containment.add(key)
                return builder(entity_value)
        return None

    def investigate(self, parsed):
        report_gaps = {key for key, value in self.report_tracker.values.items() if value == "unknown"}
        if "attacker_domain" in report_gaps and not self.registry.best_entities("domain"):
            return self.sql_planner.action_for_sql(self.sql_planner.next_broad_query(report_gaps))
        if "data_target" in report_gaps and not self.registry.best_entities("target"):
            return self.sql_planner.action_for_sql(self.sql_planner.next_broad_query(report_gaps))

        for entity_type in ("domain", "target", "host", "user"):
            for entity_value in self.registry.best_entities(entity_type):
                if entity_value == "unknown":
                    continue
                action = self.sql_planner.query_for_entity(entity_value, entity_type)
                if action.params["sql"] not in self.sql_planner.failed_queries:
                    return action
        return self.sql_planner.action_for_sql(self.sql_planner.next_broad_query(report_gaps))

    def record_failed_query(self, parsed) -> None:
        result = parsed.last_action_result or {}
        data = result.get("data") or {}
        if result.get("message") == "query_logs" and data.get("ok") is False:
            if self.sql_planner.last_emitted_sql:
                self.sql_planner.record_failure(self.sql_planner.last_emitted_sql)

    def deadline_step(self) -> int:
        if self.report_deadline_step is not None:
            return min(self.report_deadline_step, self.max_steps - 1)
        return self.max_steps - 1

    def early_report_step(self) -> int:
        return max(0, self.deadline_step() - 2)

    def containment_window_open(self, step_index: int) -> bool:
        if self.report_tracker.is_complete():
            return step_index >= self.containment_min_step
        late_containment_step = max(self.containment_min_step, self.deadline_step() - 3)
        return step_index >= late_containment_step

    def should_submit_deadline_report(self, parsed) -> bool:
        return parsed.step_index >= self.deadline_step()

    def should_submit_complete_report(self, parsed) -> bool:
        return parsed.step_index >= self.early_report_step() and self.report_tracker.is_complete()

    def build_report(self, containment: dict[str, Any]) -> dict[str, Any]:
        return self.report_tracker.report(containment)

    def mark_containment_attempted(self, action_type: str, entity_value: str) -> None:
        self.attempted_containment.add((action_type, entity_value))

    # Backward-compatible aliases for older tests and local helper code.
    _next_unseen_fetch = next_unseen_fetch
    _next_gated_containment = next_gated_containment
    _investigate = investigate
    _record_failed_query = record_failed_query
    _report_deadline_step = deadline_step
    _early_report_step = early_report_step
    _containment_window_open = containment_window_open
