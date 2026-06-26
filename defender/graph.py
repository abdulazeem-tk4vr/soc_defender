from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .budget import budget_state
from .graph_state import DefenderGraphState
from .investigator import InvestigationIntent, Investigator, LLMVerifier, VerifierCandidate
from .observation import parse_observation
from .policy import DefenderPolicy
from .rag import RAGIntel
from .responder import Responder, action_payload, verified_candidate_payload
from .scanner import InjectionScanner


@dataclass
class DefenderGraph:
    policy: DefenderPolicy = field(default_factory=DefenderPolicy)
    scanner: InjectionScanner = field(default_factory=InjectionScanner)
    rag: RAGIntel = field(default_factory=RAGIntel)
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
        state.episode_summary = dict(self.policy.episode_summary)
        self._scanner_node(state)
        self._registry_node(state)
        self._budget_node(state)
        self._investigator_node(state)
        self._rag_node(state)
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

    def _rag_node(self, state: DefenderGraphState) -> None:
        intent = InvestigationIntent(**state.investigation_intent)
        query = intent.rag_query or state.rag_query or self.policy.rag_query_cache
        state.rag_query = query
        step_index = state.open_sec_step_index
        if self.policy.rag_called:
            state.rag_query = self.policy.rag_query_cache or query
            state.rag_context = list(self.policy.rag_context_cache)
            state.append_trace(
                "rag",
                {
                    "strategy": "single_episode_rag",
                    "query": state.rag_query,
                    "documents": len(state.rag_context),
                    "top_documents": [
                        {"source": doc.get("source"), "title": doc.get("title")}
                        for doc in state.rag_context[:3]
                    ],
                    "rag_cost": 0,
                    "cache_hit": True,
                    "rag_called": True,
                    "rag_call_step": self.policy.rag_call_step,
                },
            )
            return

        if step_index < 3 or not query:
            state.rag_context = []
            state.append_trace(
                "rag",
                {
                    "strategy": "single_episode_rag",
                    "query": query,
                    "documents": 0,
                    "top_documents": [],
                    "rag_cost": 0,
                    "cache_hit": False,
                    "rag_called": False,
                    "rag_call_step": None,
                    "skipped_reason": "wait_until_step_3",
                },
            )
            return

        docs = self.rag.context_for(query)
        state.rag_context = [asdict(doc) for doc in docs]
        self.policy.rag_context_cache = list(state.rag_context)
        self.policy.rag_query_cache = query
        self.policy.rag_called = True
        self.policy.rag_call_step = step_index
        state.append_trace(
            "rag",
            {
                "strategy": "single_episode_rag",
                "query": query,
                "documents": len(docs),
                "top_documents": [{"source": doc.source, "title": doc.title} for doc in docs[:3]],
                "rag_cost": 1,
                "cache_hit": False,
                "rag_called": True,
                "rag_call_step": step_index,
            },
        )

    def _investigator_node(self, state: DefenderGraphState) -> None:
        observation = dict(state.observation)
        observation.update(
            {
                "query_history": self.policy.compact_query_history(),
                "tried_approaches": self.policy.tried_approaches(),
                "rag_called": self.policy.rag_called,
                "rag_query_cache": self.policy.rag_query_cache,
                "known_entities": sorted(self.policy.known_entities()),
            }
        )
        intent = self.investigator.investigate(
            observation,
            self.policy.registry,
            self.policy.report_tracker,
            rag_context=state.rag_context,
            scanner_annotations=state.scanner_annotations,
            budget_state=state.budget_state,
            episode_summary=state.episode_summary,
        )
        intent = self._ground_intent(intent, state)
        state.investigation_intent = asdict(intent)
        state.rag_query = intent.rag_query
        state.append_trace("investigator", state.investigation_intent)

    def _ground_intent(self, intent: InvestigationIntent, state: DefenderGraphState) -> InvestigationIntent:
        value = intent.entity_value
        if intent.rag_query and self.policy.rag_called:
            intent = InvestigationIntent(
                intent.intent_type,
                intent.entity_type,
                intent.entity_value,
                intent.rationale,
                intent.confidence,
                intent.evidence_summary,
                intent.uncertainty,
                "",
            )
        if intent.intent_type != "query_logs" or not value:
            return intent
        if value in self.policy.known_entities():
            return intent
        state.append_trace(
            "grounding",
            {
                "rejected_entity": value,
                "reason": "query_logs entity not grounded in known entities",
            },
        )
        return InvestigationIntent(
            "query_logs",
            None,
            None,
            "entity not grounded; falling back to policy investigation",
            0.0,
            intent.evidence_summary,
            intent.uncertainty,
            intent.rag_query,
        )

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
        verifier_budget = dict(state.budget_state)
        verifier_budget.update(
            {
                "query_history": self.policy.compact_query_history(),
                "tried_approaches": self.policy.tried_approaches(),
                "rag_called": self.policy.rag_called,
                "rag_query_cache": self.policy.rag_query_cache,
                "known_entities": sorted(self.policy.known_entities()),
            }
        )
        candidate = self.verifier.candidate(
            intent,
            self.policy.registry,
            self.policy.report_tracker,
            verifier_budget,
            rag_context=state.rag_context,
            scanner_annotations=state.scanner_annotations,
            episode_summary=state.episode_summary,
        )
        state.verifier_candidate = asdict(candidate)
        if candidate.episode_summary:
            self.policy.episode_summary = dict(candidate.episode_summary)
            state.episode_summary = dict(candidate.episode_summary)
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
