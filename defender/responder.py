from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .actions import block_domain, fetch_alert, fetch_email, isolate_host, reset_user, submit_report, is_safe_select
from .prompt_context import report_gaps
from .investigator import InvestigationIntent, VerifierCandidate
from .observation import ParsedObservation
from .policy import DefenderPolicy
from .verifier import GateDecision, gate_containment


CONTAINMENT_BUILDERS = {
    "isolate_host": isolate_host,
    "block_domain": block_domain,
    "reset_user": reset_user,
}


@dataclass(frozen=True)
class VerifiedActionCandidate:
    action_type: str
    entity_value: str | None = None
    gate_decision: GateDecision | None = None
    rationale: str = ""
    confidence: float = 0.0


@dataclass
class Responder:
    policy: DefenderPolicy

    def respond(
        self,
        parsed: ParsedObservation,
        intent: InvestigationIntent,
        candidate: VerifierCandidate,
    ) -> tuple[Any, VerifiedActionCandidate]:
        verified = self._verify_candidate(parsed, candidate)

        if parsed.step_index >= self.policy._report_deadline_step():
            return submit_report(self.policy.report_tracker.report(parsed.containment)), verified

        if verified.action_type == "submit_report" and self.policy.report_tracker.is_complete():
            return submit_report(self.policy.report_tracker.report(parsed.containment)), verified

        report_fill_phase = parsed.step_index >= self.policy._report_deadline_step() - 2
        if verified.gate_decision and verified.gate_decision.approved and verified.entity_value and not report_fill_phase:
            builder = CONTAINMENT_BUILDERS[verified.action_type]
            self.policy.attempted_containment.add((verified.action_type, verified.entity_value))
            return builder(verified.entity_value), verified

        if self.policy._containment_window_open(parsed.step_index):
            containment = self.policy._next_gated_containment(parsed.step_index, parsed.containment)
            if containment is not None:
                return containment, verified

        action = self._action_from_intent(parsed, intent)
        if action is not None and intent.intent_type == "query_logs":
            return action, verified

        unseen = self.policy._next_unseen_fetch(parsed)
        if unseen is not None:
            return unseen, verified

        if action is not None:
            return action, verified

        return self.policy._investigate(parsed), verified

    def _verify_candidate(
        self,
        parsed: ParsedObservation,
        candidate: VerifierCandidate,
    ) -> VerifiedActionCandidate:
        if candidate.action_type in CONTAINMENT_BUILDERS and candidate.entity_value:
            decision = gate_containment(
                candidate.action_type,
                candidate.entity_value,
                self.policy.registry,
                step_index=parsed.step_index,
                containment_min_step=self.policy.containment_min_step,
            )
            return VerifiedActionCandidate(
                action_type=candidate.action_type,
                entity_value=candidate.entity_value,
                gate_decision=decision,
                rationale=candidate.rationale,
                confidence=candidate.confidence,
            )
        return VerifiedActionCandidate(
            action_type=candidate.action_type,
            entity_value=candidate.entity_value,
            rationale=candidate.rationale,
            confidence=candidate.confidence,
        )

    def _action_from_intent(self, parsed: ParsedObservation, intent: InvestigationIntent):
        if intent.intent_type == "fetch_alert":
            alert_id = intent.entity_value if intent.entity_value in parsed.new_alerts else None
            alert_id = alert_id or next((item for item in parsed.new_alerts if item not in self.policy.fetched_alerts), None)
            if alert_id:
                self.policy.fetched_alerts.add(alert_id)
                return fetch_alert(alert_id)
        if intent.intent_type == "fetch_email":
            email_id = intent.entity_value if intent.entity_value in parsed.new_emails else None
            email_id = email_id or next((item for item in parsed.new_emails if item not in self.policy.fetched_emails), None)
            if email_id:
                self.policy.fetched_emails.add(email_id)
                return fetch_email(email_id)
        if intent.intent_type == "query_logs" and intent.sql and is_safe_select(intent.sql):
            return self.policy.sql_planner.action_for_sql(intent.sql)
        if intent.intent_type == "query_logs" and (intent.source_table or intent.objective):
            gaps = set(report_gaps(self.policy.report_tracker.values))
            objective = self.policy._progress_guarded_objective(intent.objective, gaps)
            return self.policy.sql_planner.query_for_objective_source(objective, intent.source_table, gaps)
        if intent.intent_type == "query_logs" and intent.entity_value:
            return self.policy.sql_planner.query_for_entity(intent.entity_value, intent.entity_type or "")
        return None


def action_payload(action: Any) -> dict[str, Any]:
    if hasattr(action, "model_dump"):
        return action.model_dump()
    return {"action_type": action.action_type, "params": action.params}


def verified_candidate_payload(candidate: VerifiedActionCandidate) -> dict[str, Any]:
    payload = asdict(candidate)
    decision = candidate.gate_decision
    if decision is not None:
        payload["gate_decision"] = {
            "approved": decision.approved,
            "reason": decision.reason,
            "support_count": len(decision.support),
        }
    return payload
