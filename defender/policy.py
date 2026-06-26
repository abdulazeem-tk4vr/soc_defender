from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .actions import block_domain, fetch_alert, fetch_email, isolate_host, reset_user, submit_report
from .evidence_registry import EvidenceRegistry
from .observation import ParsedObservation, parse_observation
from .report_readiness import ReportReadinessTracker
from .reward_policy import report_decision
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
    rag_context_cache: list[dict[str, Any]] = field(default_factory=list)
    rag_query_cache: str = ""
    rag_called: bool = False
    rag_call_step: int | None = None
    episode_summary: dict[str, Any] = field(default_factory=dict)
    last_evidence_delta: dict[str, Any] = field(default_factory=dict)
    recent_zero_value_steps: int = 0
    last_report_decision: dict[str, Any] = field(default_factory=dict)

    def next_action(self, observation: dict[str, Any]):
        parsed = parse_observation(observation)
        self.ensure_scenario(parsed)
        self._update_evidence_context(parsed)

        if parsed.step_index >= self._report_deadline_step():
            decision = report_decision(self, parsed)
            self.last_report_decision = decision.to_dict()
            return submit_report(self.report_tracker.report(parsed.containment))

        if self._containment_window_open(parsed.step_index):
            containment = self._next_gated_containment(parsed.step_index, parsed.containment)
            if containment is not None:
                return containment

        decision = report_decision(self, parsed)
        self.last_report_decision = decision.to_dict()
        if decision.submit:
            return submit_report(self.report_tracker.report(parsed.containment))

        action = self._next_unseen_fetch(parsed)
        if action is not None:
            return action

        return self._investigate(parsed)

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
        self.rag_context_cache.clear()
        self.rag_query_cache = ""
        self.rag_called = False
        self.rag_call_step = None
        self.episode_summary.clear()
        self.last_evidence_delta.clear()
        self.recent_zero_value_steps = 0
        self.last_report_decision.clear()
        self.current_scenario_id = scenario_id

    def _next_unseen_fetch(self, parsed):
        for alert_id in parsed.new_alerts:
            if alert_id not in self.fetched_alerts:
                self.fetched_alerts.add(alert_id)
                return fetch_alert(alert_id)
        for email_id in parsed.new_emails:
            if email_id not in self.fetched_emails:
                self.fetched_emails.add(email_id)
                return fetch_email(email_id)
        return None

    def _next_gated_containment(self, step_index: int, containment: dict[str, list[str]]):
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

    def _investigate(self, parsed):
        report_gaps = {key for key, value in self.report_tracker.values.items() if value == "unknown"}
        if "attacker_domain" in report_gaps and not self.registry.best_entities("domain"):
            return self.sql_planner.action_for_sql(self.sql_planner.next_broad_query(report_gaps))
        if "data_target" in report_gaps and not self.registry.best_entities("target"):
            return self.sql_planner.action_for_sql(self.sql_planner.next_broad_query(report_gaps))

        for entity_type in ("domain", "target", "host", "user"):
            for entity_value in self.registry.best_entities(entity_type):
                if entity_value == "unknown":
                    continue
                action = self.sql_planner.query_for_entity(entity_value, entity_type, report_gaps)
                if action.params["sql"] not in self.sql_planner.failed_queries:
                    return action
        return self.sql_planner.action_for_sql(self.sql_planner.next_broad_query(report_gaps))

    def _update_evidence_context(self, parsed) -> None:
        before_values = dict(self.report_tracker.values)
        delta = self.registry.update_from_observation(parsed)
        self.report_tracker.update(self.registry)
        changed_fields = tuple(
            sorted(
                field
                for field, value in self.report_tracker.values.items()
                if before_values.get(field) != value
            )
        )
        self.last_evidence_delta = {
            "new_support_count": delta.new_support_count,
            "new_entities_by_type": delta.new_entities_by_type,
            "changed_report_fields": changed_fields,
        }
        useful = bool(delta.new_support_count or changed_fields)
        if parsed.last_action_result.get("message") in {"query_logs", "fetch_email", "fetch_alert"}:
            self.recent_zero_value_steps = 0 if useful else self.recent_zero_value_steps + 1
        self._record_failed_query(parsed)

    def _record_failed_query(self, parsed) -> None:
        result = parsed.last_action_result or {}
        data = result.get("data") or {}
        if result.get("message") != "query_logs" or not self.sql_planner.last_emitted_sql:
            return
        rows = data.get("rows") if isinstance(data, dict) else []
        rows_returned = len(rows) if isinstance(rows, list) else 0
        ok = bool(data.get("ok", result.get("ok", True))) if isinstance(data, dict) else bool(result.get("ok", True))
        self.sql_planner.record_result(
            self.sql_planner.last_emitted_sql,
            rows_returned,
            ok=ok,
            new_support_count=int(self.last_evidence_delta.get("new_support_count") or 0),
            changed_report_fields=tuple(self.last_evidence_delta.get("changed_report_fields") or ()),
        )
        if ok is False:
            self.sql_planner.record_failure(self.sql_planner.last_emitted_sql)

    def compact_query_history(self) -> list[dict[str, Any]]:
        return self.sql_planner.compact_history()

    def tried_approaches(self) -> list[str]:
        return self.sql_planner.tried_approaches()

    def known_entities(self) -> set[str]:
        known = set(self.registry.content_ids) | set(self.registry.seen_ids)
        for value in self.report_tracker.values.values():
            if value and value != "unknown" and isinstance(value, str):
                known.add(value)
        for kind in ("host", "user", "domain", "target"):
            known.update(self.registry.best_entities(kind))
        return known

    def _report_deadline_step(self) -> int:
        if self.report_deadline_step is not None:
            return min(self.report_deadline_step, self.max_steps - 1)
        return self.max_steps - 1

    def _early_report_step(self) -> int:
        return max(0, self._report_deadline_step() - 2)

    def _containment_window_open(self, step_index: int) -> bool:
        if self.report_tracker.is_complete():
            return step_index >= self.containment_min_step
        late_containment_step = max(self.containment_min_step, self._report_deadline_step() - 3)
        return step_index >= late_containment_step
