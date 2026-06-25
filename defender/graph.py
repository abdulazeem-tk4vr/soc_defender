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
    rag_refresh_interval: int = 4
    _rag_signature: tuple[Any, ...] | None = field(init=False, default=None)
    _rag_query: str = field(init=False, default="")
    _rag_query_source: str = field(init=False, default="")
    _rag_query_rationale: str = field(init=False, default="")
    _rag_context: list[dict[str, Any]] = field(init=False, default_factory=list)
    _rag_step: int = field(init=False, default=-1)


    def reset_episode_cache(self) -> None:
        self._rag_signature = None
        self._rag_query = ""
        self._rag_query_source = ""
        self._rag_query_rationale = ""
        self._rag_context = []
        self._rag_step = -1

    def next_action(self, observation: dict[str, Any]) -> tuple[dict[str, Any], DefenderGraphState]:
        state = DefenderGraphState(
            scenario_id=str(observation.get("scenario_id") or ""),
            open_sec_step_index=int(observation.get("step_index") or 0),
            max_steps=self.policy.max_steps,
            observation=dict(observation),
        )
        state.parsed_observation = parse_observation(observation)
        if self.policy.ensure_scenario(state.parsed_observation):
            self.reset_episode_cache()
        self._scanner_node(state)
        self._registry_node(state)
        self._rag_query_node(state)
        self._rag_node(state)
        self._budget_node(state)
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
        state.append_trace("registry", self.policy.ingest_observation(parsed))

    def _rag_query_node(self, state: DefenderGraphState) -> None:
        signature = self._rag_input_signature(state)
        refresh_due = (
            self._rag_signature != signature
            or not self._rag_query
            or state.open_sec_step_index - self._rag_step >= self.rag_refresh_interval
        )
        if refresh_due:
            plan = RAGQueryPlanner().plan(state.observation, self.policy.registry, self.policy.report_tracker)
            self._rag_signature = signature
            self._rag_query = plan.query
            self._rag_query_source = plan.source
            self._rag_query_rationale = plan.rationale
            self._rag_step = state.open_sec_step_index
            source = plan.source
            rationale = plan.rationale
        else:
            source = self._rag_query_source or "cache"
            rationale = self._rag_query_rationale or "RAG query input signature unchanged"
        state.rag_query = self._rag_query
        state.append_trace(
            "rag_query",
            {
                "query": state.rag_query,
                "source": source,
                "rationale": rationale,
                "cache_hit": not refresh_due,
                "refresh_interval": self.rag_refresh_interval,
            },
        )

    def _rag_node(self, state: DefenderGraphState) -> None:
        query = state.rag_query or self._rag_query
        cache_hit = bool(self._rag_context and query == self._rag_query and state.open_sec_step_index != self._rag_step)
        if cache_hit:
            state.rag_context = list(self._rag_context)
            docs = []
        else:
            docs = self.rag.context_for(query)
            state.rag_context = [asdict(doc) for doc in docs]
            self._rag_context = list(state.rag_context)
        state.append_trace(
            "rag",
            {
                "query": query,
                "documents": len(state.rag_context),
                "cache_hit": cache_hit,
                "top_documents": [
                    {
                        "source": doc.get("source"),
                        "title": doc.get("title"),
                        "corpus": doc.get("corpus"),
                        "containment_authority": doc.get("containment_authority"),
                    }
                    for doc in state.rag_context[:3]
                ],
            },
        )

    def _investigator_node(self, state: DefenderGraphState) -> None:
        intent = self.investigator.investigate(
            state.observation,
            self.policy.registry,
            self.policy.report_tracker,
            rag_context=state.rag_context,
            scanner_annotations=state.scanner_annotations,
            budget_state=state.budget_state,
        )
        state.investigation_intent = asdict(intent)
        self._update_rag_query_from_investigator(state, intent)
        state.append_trace("investigator", state.investigation_intent)


    def _update_rag_query_from_investigator(self, state: DefenderGraphState, intent: InvestigationIntent) -> None:
        query = RAGQueryPlanner._clean_query(intent.rag_query)
        if not query:
            return
        signature = self._rag_input_signature(state)
        if query == self._rag_query and self._rag_signature == signature:
            self._rag_query_source = "investigator"
            self._rag_query_rationale = intent.rag_rationale
            return
        self._rag_signature = signature
        self._rag_query = query
        self._rag_query_source = "investigator"
        self._rag_query_rationale = intent.rag_rationale
        self._rag_context = []
        self._rag_step = state.open_sec_step_index

    def _budget_node(self, state: DefenderGraphState) -> None:
        deadline = self.policy.deadline_step()
        state.budget_state = budget_state(
            step_index=state.open_sec_step_index,
            max_steps=self.policy.max_steps,
            report_deadline_step=deadline,
            containment_min_step=int(self.policy.containment_min_step or 0),
        ).to_dict()
        state.append_trace("budget", state.budget_state)

    def _verifier_node(self, state: DefenderGraphState) -> None:
        intent = InvestigationIntent(**state.investigation_intent)
        parsed = state.parsed_observation or parse_observation(state.observation)
        containment_context = self.policy.containment_candidate_context(parsed.step_index, parsed.containment)
        candidate = self.verifier.candidate(
            intent,
            self.policy.registry,
            self.policy.report_tracker,
            state.budget_state,
            rag_context=state.rag_context,
            scanner_annotations=state.scanner_annotations,
            containment_candidates=containment_context,
        )
        candidate, source = self._candidate_after_budget_constraints(candidate, parsed.step_index, containment_context)
        state.verifier_candidate = asdict(candidate)
        state.append_trace(
            "verifier",
            {
                **state.verifier_candidate,
                "source": source,
                "containment_candidates": containment_context,
            },
        )
        self._verified_report_fields_node(state)


    def _candidate_after_budget_constraints(
        self,
        candidate: VerifierCandidate,
        step_index: int,
        containment_context: dict[str, Any],
    ) -> tuple[VerifierCandidate, str]:
        if step_index >= self.policy.deadline_step():
            return (
                VerifierCandidate(
                    action_type="submit_report",
                    entity_value=None,
                    rationale="report deadline reached",
                    confidence=1.0,
                    report_choices=candidate.report_choices,
                    report_rankings=candidate.report_rankings,
                    report_review_source=candidate.report_review_source,
                ),
                "policy_deadline",
            )

        approved = containment_context.get("approved") if isinstance(containment_context, dict) else []
        approved = approved if isinstance(approved, list) else []
        approved_keys = {(item.get("action_type"), item.get("entity_value")) for item in approved if isinstance(item, dict)}
        if containment_context.get("must_use_pre_report_slot") and approved:
            if (candidate.action_type, candidate.entity_value) in approved_keys:
                return candidate, "llm"
            selected = approved[0]
            return (
                VerifierCandidate(
                    action_type=str(selected.get("action_type") or "investigate"),
                    entity_value=str(selected.get("entity_value") or ""),
                    rationale="pre-report containment slot reserved for approved evidence-backed containment",
                    confidence=1.0,
                    report_choices=candidate.report_choices,
                    report_rankings=candidate.report_rankings,
                    report_review_source=candidate.report_review_source,
                ),
                "policy_report_fill_override",
            )
        return candidate, "llm"


    def _verified_report_fields_node(self, state: DefenderGraphState) -> None:
        candidate = VerifierCandidate(**state.verifier_candidate)
        choices = candidate.report_choices if isinstance(candidate.report_choices, dict) else {}
        applied = self.policy.report_tracker.apply_verified_choices(self.policy.registry, choices)
        state.append_trace(
            "verified_report_fields",
            {
                "source": candidate.report_review_source,
                "choices": choices,
                "rankings": candidate.report_rankings if isinstance(candidate.report_rankings, dict) else {},
                "accepted": applied["accepted"],
                "rejected": applied["rejected"],
                "report_values": dict(self.policy.report_tracker.values),
            },
        )


    def _rag_input_signature(self, state: DefenderGraphState) -> tuple[Any, ...]:
        return (
            state.observation.get("attacker_state"),
            tuple(state.observation.get("new_alerts") or ()),
            tuple(state.observation.get("new_emails") or ()),
            tuple(sorted(self.policy.report_tracker.values.items())),
            tuple((kind, tuple(self.policy.registry.best_entities(kind)[:3])) for kind in ("host", "user", "domain", "target")),
        )

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
