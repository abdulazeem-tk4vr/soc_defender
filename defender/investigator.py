from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .evidence_registry import EvidenceRegistry
from .llm import LLMClient
from .report_readiness import ReportReadinessTracker


@dataclass(frozen=True)
class InvestigationIntent:
    intent_type: str
    entity_type: str | None = None
    entity_value: str | None = None
    rationale: str = ""
    confidence: float = 0.0
    evidence_summary: str = ""
    uncertainty: str = ""


@dataclass
class Investigator:
    llm: LLMClient | None = None

    def investigate(
        self,
        observation: dict[str, Any],
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
        rag_context: list[dict[str, Any]] | None = None,
        scanner_annotations: list[dict[str, Any]] | None = None,
        budget_state: dict[str, Any] | None = None,
    ) -> InvestigationIntent:
        if self.llm is None:
            return self._deterministic_intent(registry, report_tracker)
        try:
            response = self.llm.complete_json(
                [
                    {"role": "system", "content": "You are an SOC evidence investigator. Output investigation intent only."},
                    {
                        "role": "user",
                        "content": self._state_summary(
                            observation,
                            registry,
                            report_tracker,
                            rag_context=rag_context,
                            scanner_annotations=scanner_annotations,
                            budget_state=budget_state,
                        ),
                    },
                ],
                schema_hint={
                    "intent_type": "query_logs|fetch_alert|fetch_email|wait",
                    "entity_type": "host|user|domain|target|null",
                    "entity_value": "string|null",
                    "rationale": "string",
                    "confidence": 0.0,
                    "evidence_summary": "string",
                    "uncertainty": "string",
                },
            )
            return self._intent_from_response(response)
        except Exception:
            return self._deterministic_intent(registry, report_tracker)

    @staticmethod
    def _intent_from_response(response: dict[str, Any]) -> InvestigationIntent:
        intent_type = str(response.get("intent_type") or "query_logs")
        if intent_type not in {"query_logs", "fetch_alert", "fetch_email", "wait"}:
            intent_type = "query_logs"
        entity_type = response.get("entity_type")
        if entity_type not in {"host", "user", "domain", "target", None}:
            entity_type = None
        return InvestigationIntent(
            intent_type=intent_type,
            entity_type=entity_type,
            entity_value=response.get("entity_value"),
            rationale=str(response.get("rationale") or ""),
            confidence=max(0.0, min(1.0, float(response.get("confidence") or 0.0))),
            evidence_summary=str(response.get("evidence_summary") or ""),
            uncertainty=str(response.get("uncertainty") or ""),
        )

    @staticmethod
    def _deterministic_intent(registry: EvidenceRegistry, report_tracker: ReportReadinessTracker) -> InvestigationIntent:
        if report_tracker.values.get("data_target") == "unknown":
            for host in registry.best_entities("host"):
                return InvestigationIntent("query_logs", "host", host, "Find process/data access evidence.", 0.5)
        if report_tracker.values.get("attacker_domain") == "unknown":
            for domain in registry.best_entities("domain"):
                return InvestigationIntent("query_logs", "domain", domain, "Corroborate external domain evidence.", 0.5)
        return InvestigationIntent("query_logs", None, None, "Continue broad evidence collection.", 0.3)

    @staticmethod
    def _state_summary(
        observation: dict[str, Any],
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
        rag_context: list[dict[str, Any]] | None = None,
        scanner_annotations: list[dict[str, Any]] | None = None,
        budget_state: dict[str, Any] | None = None,
    ) -> str:
        supports = [
            {
                "entity": support.entity_value,
                "type": support.entity_type,
                "source": support.source_table,
                "scanner": support.scanner_status,
                "indicators": support.malicious_indicators,
            }
            for support in registry.supports[-20:]
        ]
        return json.dumps(
            {
                "step_index": observation.get("step_index"),
                "attacker_state": observation.get("attacker_state"),
                "new_alerts": observation.get("new_alerts"),
                "new_emails": observation.get("new_emails"),
                "report_values": report_tracker.values,
                "recent_support": supports,
                "rag_context": rag_context or [],
                "scanner_annotations": scanner_annotations or [],
                "budget": budget_state or {},
            }
        )


@dataclass(frozen=True)
class VerifierCandidate:
    action_type: str
    entity_value: str | None = None
    rationale: str = ""
    confidence: float = 0.0


@dataclass
class LLMVerifier:
    llm: LLMClient | None = None

    def candidate(
        self,
        intent: InvestigationIntent,
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
        budget_state: dict[str, Any],
        rag_context: list[dict[str, Any]] | None = None,
        scanner_annotations: list[dict[str, Any]] | None = None,
    ) -> VerifierCandidate:
        if self.llm is None:
            return VerifierCandidate("investigate", intent.entity_value, intent.rationale, intent.confidence)
        try:
            response = self.llm.complete_json(
                [
                    {"role": "system", "content": "You are an SOC verifier. Choose investigation, containment candidate, or report."},
                    {
                        "role": "user",
                        "content": str(
                            {
                                "intent": intent,
                                "report_values": report_tracker.values,
                                "budget": budget_state,
                                "rag_context": rag_context or [],
                                "scanner_annotations": scanner_annotations or [],
                                "entities": {kind: registry.best_entities(kind) for kind in ("host", "user", "domain", "target")},
                            }
                        ),
                    },
                ],
                schema_hint={"action_type": "investigate|isolate_host|block_domain|reset_user|submit_report", "entity_value": "string|null", "rationale": "string", "confidence": 0.0},
            )
            return self._candidate_from_response(response)
        except Exception:
            return VerifierCandidate("investigate", intent.entity_value, intent.rationale, intent.confidence)

    @staticmethod
    def _candidate_from_response(response: dict[str, Any]) -> VerifierCandidate:
        action_type = str(response.get("action_type") or "investigate")
        if action_type not in {"investigate", "isolate_host", "block_domain", "reset_user", "submit_report"}:
            action_type = "investigate"
        return VerifierCandidate(
            action_type=action_type,
            entity_value=response.get("entity_value"),
            rationale=str(response.get("rationale") or ""),
            confidence=max(0.0, min(1.0, float(response.get("confidence") or 0.0))),
        )
