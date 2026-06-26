from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .budget import budget_state
from .graph_state import DefenderGraphState
from .investigator import InvestigationIntent, Investigator, LLMVerifier, VerifierCandidate
from .observation import parse_observation
from .policy import DefenderPolicy
from .rag import RAGIntel
from .rag_query import RAGQueryPlanner
from .responder import Responder, action_payload, verified_candidate_payload
from .scanner import InjectionScanner


@dataclass
class DefenderGraph:
    policy: DefenderPolicy = field(default_factory=DefenderPolicy)
    scanner: InjectionScanner = field(default_factory=InjectionScanner)
    rag: RAGIntel = field(default_factory=RAGIntel)
    rag_query_planner: RAGQueryPlanner = field(default_factory=RAGQueryPlanner)
    investigator: Investigator = field(default_factory=Investigator)
    verifier: LLMVerifier = field(default_factory=LLMVerifier)

    def next_action(self, observation: dict[str, Any]) -> tuple[dict[str, Any], DefenderGraphState]:
        state = DefenderGraphState(
            scenario_id=str(observation.get("scenario_id") or ""),
            open_sec_step_index=int(observation.get("step_index") or 0),
            max_steps=self.policy.max_steps,
            observation=dict(observation),
        )
        state.parsed_observation = parse_observation(observation)
        self.policy.ensure_scenario(state.parsed_observation)
        self._scanner_node(state)
        self._registry_node(state)
        self._rag_query_node(state)
        self._rag_node(state)
        self._budget_node(state)
        self._ml_advisory_node(state)
        self._investigator_node(state)
        self._verifier_node(state)
        action = self._responder_node(state)
        return action, state

    def _scanner_node(self, state: DefenderGraphState) -> None:
        texts = []
        result = state.observation.get("last_action_result") or {}
        data = result.get("data") or {}
        if isinstance(data, dict):
            texts.extend(str(value) for value in data.values() if isinstance(value, str))
        annotations = []
        for text in texts:
            scan = self.scanner.scan_text(text)
            annotations.append(
                {
                    "status": scan.status,
                    "max_confidence": scan.max_confidence,
                    "rule_ids": [finding.rule_id for finding in scan.findings],
                }
            )
        state.scanner_annotations = annotations
        state.append_trace("scanner", {"annotations": annotations})

    def _registry_node(self, state: DefenderGraphState) -> None:
        parsed = state.parsed_observation or parse_observation(state.observation)
        before = len(self.policy.registry.supports)
        self.policy.registry.update_from_observation(parsed)
        self.policy.report_tracker.update(self.policy.registry)
        self.policy._record_failed_query(parsed)
        state.append_trace(
            "registry",
            {
                "supports_before_action": before,
                "supports_after_update": len(self.policy.registry.supports),
                "report_values": dict(self.policy.report_tracker.values),
            },
        )

    def _rag_query_node(self, state: DefenderGraphState) -> None:
        plan = self.rag_query_planner.plan(state.observation, self.policy.registry, self.policy.report_tracker)
        state.rag_query = plan.query
        state.append_trace(
            "rag_query",
            {
                "query": plan.query,
                "source": plan.source,
                "rationale": plan.rationale,
            },
        )

    def _rag_node(self, state: DefenderGraphState) -> None:
        query = state.rag_query or self.rag_query_planner.plan(
            state.observation,
            self.policy.registry,
            self.policy.report_tracker,
        ).query
        docs = self.rag.context_for(query)
        state.rag_context = [asdict(doc) for doc in docs]
        state.append_trace(
            "rag",
            {
                "query": query,
                "documents": len(docs),
                "top_documents": [{"source": doc.source, "title": doc.title} for doc in docs[:3]],
            },
        )


    def _ml_advisory_node(self, state: DefenderGraphState) -> None:
        calibrator = self.policy.ml_calibrator
        if calibrator is None:
            state.ml_advisory = {"available": False, "reason": "disabled"}
            state.append_trace("ml_advisory", state.ml_advisory)
            return
        objective_scores = calibrator.score_objectives(self.policy, state.parsed_observation).to_dict()
        containment_scores = []
        for action_type, entity_type in (
            ("isolate_host", "host"),
            ("reset_user", "user"),
            ("block_domain", "domain"),
        ):
            for entity_value in self.policy.registry.best_entities(entity_type)[:3]:
                containment_scores.append(calibrator.score_containment(action_type, entity_value, self.policy).to_dict())
        state.ml_advisory = {
            "available": bool(objective_scores.get("available")),
            "objectives": objective_scores,
            "containment": containment_scores,
            "artifact": {
                "example_count": calibrator.manifest.get("example_count"),
                "training_status": calibrator.manifest.get("training_status"),
            },
        }
        self.policy.last_ml_objective_scores = objective_scores
        self.policy.last_ml_containment_scores = containment_scores
        state.append_trace("ml_advisory", state.ml_advisory)

    def _investigator_node(self, state: DefenderGraphState) -> None:
        intent = self.investigator.investigate(
            state.observation,
            self.policy.registry,
            self.policy.report_tracker,
            rag_context=state.rag_context,
            scanner_annotations=state.scanner_annotations,
            budget_state=state.budget_state,
            ml_advisory=state.ml_advisory,
        )
        state.investigation_intent = asdict(intent)
        state.append_trace("investigator", state.investigation_intent)

    def _budget_node(self, state: DefenderGraphState) -> None:
        deadline = self.policy._report_deadline_step()
        state.budget_state = budget_state(
            step_index=state.open_sec_step_index,
            max_steps=self.policy.max_steps,
            report_deadline_step=deadline,
            containment_min_step=self.policy.containment_min_step,
        ).to_dict()
        state.append_trace("budget", state.budget_state)

    def _verifier_node(self, state: DefenderGraphState) -> None:
        intent = InvestigationIntent(**state.investigation_intent)
        candidate = self.verifier.candidate(
            intent,
            self.policy.registry,
            self.policy.report_tracker,
            state.budget_state,
            rag_context=state.rag_context,
            scanner_annotations=state.scanner_annotations,
            ml_advisory=state.ml_advisory,
        )
        state.verifier_candidate = asdict(candidate)
        state.append_trace("verifier", state.verifier_candidate)

    def _responder_node(self, state: DefenderGraphState) -> dict[str, Any]:
        responder = Responder(self.policy)
        parsed = state.parsed_observation or parse_observation(state.observation)
        intent = InvestigationIntent(**state.investigation_intent)
        candidate = VerifierCandidate(**state.verifier_candidate)
        action, verified = responder.respond(parsed, intent, candidate)
        payload = action_payload(action)
        state.responder_action = payload
        state.gate_decision = verified_candidate_payload(verified).get("gate_decision") or {}
        state.append_trace(
            "responder",
            {
                "verifier_candidate": verified_candidate_payload(verified),
                "action": payload,
            },
        )
        return payload
