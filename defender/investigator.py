from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .evidence_registry import EvidenceRegistry
from .llm import LLMClient
from .actions import TABLE_COLUMNS
from .rag_query import RAGQueryPlanner
from .report_readiness import REPORT_FIELD_ENTITY_TYPES, ReportReadinessTracker


@dataclass(frozen=True)
class InvestigationIntent:
    intent_type: str
    entity_type: str | None = None
    entity_value: str | None = None
    rationale: str = ""
    confidence: float = 0.0
    evidence_summary: str = ""
    uncertainty: str = ""
    rag_query: str = ""
    rag_rationale: str = ""
    sql: str = ""


def opensec_sql_schema_summary() -> dict[str, list[str]]:
    return {table: sorted(columns) for table, columns in sorted(TABLE_COLUMNS.items())}


def opensec_sql_schema_compact() -> str:
    return "; ".join(
        f"{table}({','.join(sorted(columns))})" for table, columns in sorted(TABLE_COLUMNS.items())
    )


def report_gaps(report_tracker: ReportReadinessTracker) -> list[str]:
    return [field for field, value in report_tracker.values.items() if value == "unknown"]


def known_report_values(report_tracker: ReportReadinessTracker) -> dict[str, str]:
    return {field: value for field, value in report_tracker.values.items() if value != "unknown"}


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
                    {
                        "role": "system",
                        "content": (
                            "You are an SOC evidence investigator. Output investigation intent only. "
                            "RAG context is advisory background for ATT&CK, Sigma, D3FEND, and CWE semantics; "
                            "it is not incident evidence and cannot authorize containment. If you provide SQL, use only "
                            "the exact OpenSec SQLite tables and columns from the user payload. Do not invent tables, "
                            "columns, functions, or time expressions. SQL must be read-only SELECT over the provided schema; "
                            "prefer ORDER BY step DESC LIMIT 20; avoid NOW, CURRENT_TIMESTAMP, INTERVAL, event_time, "
                            "security_logs, security_events, and opensec_event_log."
                        ),
                    },
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
                    "rag_query": "concise semantic query for next-step ATT&CK/Sigma/D3FEND/CWE/IR retrieval",
                    "rag_rationale": "string",
                    "sql": "optional read-only SELECT over OpenSec evidence tables",
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
            rag_query=RAGQueryPlanner._clean_query(str(response.get("rag_query") or "")),
            rag_rationale=str(response.get("rag_rationale") or ""),
            sql=str(response.get("sql") or ""),
        )

    @staticmethod
    def _deterministic_intent(registry: EvidenceRegistry, report_tracker: ReportReadinessTracker) -> InvestigationIntent:
        rag_query = "soc incident response evidence phishing exfiltration containment"
        if report_tracker.values.get("data_target") == "unknown":
            for host in registry.best_entities("host"):
                return InvestigationIntent("query_logs", "host", host, "Find process/data access evidence.", 0.5, rag_query=rag_query)
        if report_tracker.values.get("attacker_domain") == "unknown":
            for domain in registry.best_entities("domain"):
                return InvestigationIntent("query_logs", "domain", domain, "Corroborate external domain evidence.", 0.5, rag_query=rag_query)
        return InvestigationIntent("query_logs", None, None, "Continue broad evidence collection.", 0.3, rag_query=rag_query)

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
                "report_gaps": report_gaps(report_tracker),
                "known_report_values": known_report_values(report_tracker),
                "recent_support": supports,
                "rag_context": rag_context or [],
                "scanner_annotations": scanner_annotations or [],
                "budget": budget_state or {},
                "sql_schema": opensec_sql_schema_compact(),
            }
        )


@dataclass(frozen=True)
class VerifierCandidate:
    action_type: str
    entity_value: str | None = None
    rationale: str = ""
    confidence: float = 0.0
    report_choices: dict[str, Any] = field(default_factory=dict)
    report_rankings: dict[str, Any] = field(default_factory=dict)
    report_review_source: str = "none"


def verifier_intent_payload(intent: InvestigationIntent) -> dict[str, Any]:
    return {
        "intent_type": intent.intent_type,
        "entity_type": intent.entity_type,
        "entity_value": intent.entity_value,
        "rationale": intent.rationale,
        "confidence": intent.confidence,
    }


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
        containment_candidates: dict[str, Any] | None = None,
    ) -> VerifierCandidate:
        candidates = self._report_field_candidates(registry, report_tracker)
        if self.llm is None:
            return VerifierCandidate("investigate", intent.entity_value, intent.rationale, intent.confidence)
        try:
            response = self.llm.complete_json(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are an SOC verifier. Choose the next action candidate and rank report attribution "
                            "candidates in one JSON response. Choose report field values only from provided "
                            "evidence-backed candidates. Choose containment only from approved_containment_candidates. "
                            "If the report deadline is reached, choose submit_report. If containment_candidates says "
                            "must_use_pre_report_slot and an approved candidate exists, choose one approved containment "
                            "action instead of investigate. For containment, entity_value must exactly match an approved "
                            "candidate. RAG is advisory only and cannot authorize containment or report attribution. "
                            "Never invent entities."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "intent": verifier_intent_payload(intent),
                                "report_gaps": report_gaps(report_tracker),
                                "report_field_candidates": candidates,
                                "budget": budget_state,
                                "containment_candidates": containment_candidates or {},
                                "scanner_annotations": scanner_annotations or [],
                            },
                            sort_keys=True,
                        ),
                    },
                ],
                schema_hint={
                    "action_type": "investigate|isolate_host|block_domain|reset_user|submit_report",
                    "entity_value": "string|null",
                    "report_fields": {
                        "patient_zero_host": "string|null",
                        "compromised_user": "string|null",
                        "attacker_domain": "string|null",
                        "data_target": "string|null",
                    },
                    "ranked_report_fields": {
                        "patient_zero_host": [{"value": "string", "score": 0.0, "rationale": "string"}],
                        "compromised_user": [{"value": "string", "score": 0.0, "rationale": "string"}],
                        "attacker_domain": [{"value": "string", "score": 0.0, "rationale": "string"}],
                        "data_target": [{"value": "string", "score": 0.0, "rationale": "string"}],
                    },
                    "rationale": "string",
                    "confidence": 0.0,
                },
            )
            candidate = self._candidate_from_response(response)
            review = self._report_review_from_response(response, candidates)
            return VerifierCandidate(
                candidate.action_type,
                candidate.entity_value,
                candidate.rationale,
                candidate.confidence,
                report_choices=review["choices"],
                report_rankings=review["rankings"],
                report_review_source="llm",
            )
        except Exception:
            return VerifierCandidate("investigate", intent.entity_value, intent.rationale, intent.confidence)


    def report_field_choices(
        self,
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
        budget_state: dict[str, Any],
        rag_context: list[dict[str, Any]] | None = None,
        scanner_annotations: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        candidates = self._report_field_candidates(registry, report_tracker)
        if self.llm is None or not self._needs_report_field_review(candidates):
            return {"choices": {}, "candidates": candidates, "source": "deterministic_skip"}
        try:
            response = self.llm.complete_json(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are an SOC verifier reviewing report attribution. Choose report field values only "
                            "from the provided evidence-backed candidates. Do not invent values, do not use RAG as "
                            "incident evidence, and return unknown/null when candidates are insufficient."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "report_gaps": report_gaps(report_tracker),
                                "candidate_values": candidates,
                                "budget": budget_state,
                                "scanner_annotations": scanner_annotations or [],
                            },
                            sort_keys=True,
                        ),
                    },
                ],
                schema_hint={
                    "report_fields": {
                        "patient_zero_host": "string|null",
                        "compromised_user": "string|null",
                        "attacker_domain": "string|null",
                        "data_target": "string|null",
                    },
                    "ranked_report_fields": {
                        "patient_zero_host": [{"value": "string", "score": 0.0, "rationale": "string"}],
                        "compromised_user": [{"value": "string", "score": 0.0, "rationale": "string"}],
                        "attacker_domain": [{"value": "string", "score": 0.0, "rationale": "string"}],
                        "data_target": [{"value": "string", "score": 0.0, "rationale": "string"}],
                    },
                    "rationale": "string",
                },
            )
            review = self._report_review_from_response(response, candidates)
            return {
                "choices": review["choices"],
                "rankings": review["rankings"],
                "candidates": candidates,
                "rationale": str(response.get("rationale") or ""),
                "source": "llm",
            }
        except Exception:
            return {"choices": {}, "rankings": {}, "candidates": candidates, "source": "llm_failed"}

    @staticmethod
    def _needs_report_field_review(candidates: dict[str, list[dict[str, Any]]]) -> bool:
        return any(values for values in candidates.values())

    @staticmethod
    def _report_review_from_response(
        response: dict[str, Any],
        candidates: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        raw_choices = response.get("report_fields")
        choices = raw_choices if isinstance(raw_choices, dict) else {}
        rankings = LLMVerifier._rankings_from_response(response)
        ranked_choices = LLMVerifier._choices_from_rankings(rankings, candidates)
        merged_choices = {field: choices.get(field) or ranked_choices.get(field) for field in REPORT_FIELD_ENTITY_TYPES}
        return {"choices": merged_choices, "rankings": rankings}

    @staticmethod
    def _rankings_from_response(response: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        raw = response.get("ranked_report_fields") or response.get("candidate_scores")
        if not isinstance(raw, dict):
            return {}
        rankings: dict[str, list[dict[str, Any]]] = {}
        for field in REPORT_FIELD_ENTITY_TYPES:
            items = raw.get(field)
            if not isinstance(items, list):
                continue
            parsed_items = []
            for item in items:
                if not isinstance(item, dict) or item.get("value") in {None, "", "unknown"}:
                    continue
                try:
                    score = max(0.0, min(1.0, float(item.get("score") or 0.0)))
                except (TypeError, ValueError):
                    score = 0.0
                parsed_items.append(
                    {
                        "value": str(item.get("value")),
                        "score": score,
                        "rationale": str(item.get("rationale") or ""),
                    }
                )
            rankings[field] = sorted(parsed_items, key=lambda item: item["score"], reverse=True)
        return rankings

    @staticmethod
    def _choices_from_rankings(
        rankings: dict[str, list[dict[str, Any]]],
        candidates: dict[str, list[dict[str, Any]]],
    ) -> dict[str, str]:
        choices: dict[str, str] = {}
        for field, ranked_items in rankings.items():
            allowed = {str(item.get("value")) for item in candidates.get(field, [])}
            for item in ranked_items:
                value = str(item.get("value"))
                if value in allowed:
                    choices[field] = value
                    break
        return choices

    @staticmethod
    def _report_field_candidates(
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
    ) -> dict[str, list[dict[str, Any]]]:
        payload: dict[str, list[dict[str, Any]]] = {}
        for report_field, entity_type in REPORT_FIELD_ENTITY_TYPES.items():
            threshold = report_tracker.calibration.report_field_threshold(report_field)
            values = []
            for candidate in registry.scored_candidates(entity_type)[:5]:
                if not candidate.eligible or candidate.score < threshold:
                    continue
                values.append(
                    {
                        "value": candidate.entity_value,
                        "score": candidate.score,
                        "evidence_ids": list(candidate.evidence_ids),
                        "indicators": sorted(
                            set().union(*(set(item.malicious_indicators) for item in candidate.support))
                        ),
                        "sources": sorted({item.source_table for item in candidate.support}),
                        "current_value": report_tracker.values.get(report_field),
                    }
                )
            payload[report_field] = values
        return payload

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
