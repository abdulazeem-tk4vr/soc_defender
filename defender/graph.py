from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .graph_state import DefenderGraphState
from .investigator import Investigator, LLMVerifier
from .policy import DefenderPolicy
from .rag import RAGIntel
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
        self._scanner_node(state)
        self._registry_node(state)
        self._rag_node(state)
        self._investigator_node(state)
        self._budget_node(state)
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
        # The policy owns the canonical registry update path.
        state.append_trace("registry", {"supports_before_action": len(self.policy.registry.supports)})

    def _rag_node(self, state: DefenderGraphState) -> None:
        query = " ".join(
            str(value)
            for value in self.policy.report_tracker.values.values()
            if value and value != "unknown"
        ) or "soc investigation"
        docs = self.rag.context_for(query)
        state.rag_context = [asdict(doc) for doc in docs]
        state.append_trace("rag", {"documents": len(docs)})

    def _investigator_node(self, state: DefenderGraphState) -> None:
        intent = self.investigator.investigate(state.observation, self.policy.registry, self.policy.report_tracker)
        state.investigation_intent = asdict(intent)
        state.append_trace("investigator", state.investigation_intent)

    def _budget_node(self, state: DefenderGraphState) -> None:
        deadline = self.policy._report_deadline_step()
        state.budget_state = {
            "step_index": state.open_sec_step_index,
            "max_steps": self.policy.max_steps,
            "report_deadline_step": deadline,
            "steps_remaining_before_report": max(0, deadline - state.open_sec_step_index),
        }
        state.append_trace("budget", state.budget_state)

    def _verifier_node(self, state: DefenderGraphState) -> None:
        intent = self.investigator.investigate(state.observation, self.policy.registry, self.policy.report_tracker)
        candidate = self.verifier.candidate(intent, self.policy.registry, self.policy.report_tracker, state.budget_state)
        state.verifier_candidate = asdict(candidate)
        state.append_trace("verifier", state.verifier_candidate)

    def _responder_node(self, state: DefenderGraphState) -> dict[str, Any]:
        action = self.policy.next_action(state.observation)
        if hasattr(action, "model_dump"):
            payload = action.model_dump()
        else:
            payload = {"action_type": action.action_type, "params": action.params}
        state.responder_action = payload
        state.append_trace("responder", payload)
        return payload
