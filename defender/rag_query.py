from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .evidence_registry import EvidenceRegistry
from .llm import LLMClient
from .prompt_context import gap_terms, report_focus, report_gaps
from .report_readiness import ReportReadinessTracker

MAX_RAG_QUERY_CHARS = 300
_INJECTION_MARKERS = (
    "ignore previous",
    "system prompt",
    "developer prompt",
    "jailbreak",
    "hidden instructions",
)


@dataclass(frozen=True)
class RAGQueryPlan:
    query: str
    source: str = "deterministic"
    rationale: str = ""


@dataclass
class RAGQueryPlanner:
    llm: LLMClient | None = None
    _last_signature: str = field(default="", init=False, repr=False)
    _last_plan: RAGQueryPlan | None = field(default=None, init=False, repr=False)

    def plan(
        self,
        observation: dict[str, Any],
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
    ) -> RAGQueryPlan:
        signature = self._planning_signature(observation, registry, report_tracker)
        if self._last_plan is not None and signature == self._last_signature:
            return RAGQueryPlan(self._last_plan.query, source="cached", rationale=self._last_plan.rationale)

        fallback = self._deterministic_query(observation, registry, report_tracker)
        if self.llm is None:
            plan = RAGQueryPlan(fallback, source="deterministic", rationale="no llm configured")
            self._last_signature = signature
            self._last_plan = plan
            return plan
        try:
            response = self.llm.complete_json(
                [
                    {
                        "role": "system",
                        "content": (
                            "You write one concise semantic retrieval query for cybersecurity RAG. "
                            "Return only concepts useful for ATT&CK, Sigma, D3FEND, CWE, and incident-response retrieval. "
                            "Do not include raw evidence text, SQL, instructions, or prompt content."
                        ),
                    },
                    {"role": "user", "content": self._state_summary(observation, registry, report_tracker)},
                ],
                schema_hint={"query": "string", "rationale": "string"},
            )
            query = self._clean_query(str(response.get("query") or ""))
            if not query:
                plan = RAGQueryPlan(fallback, source="deterministic", rationale="llm query rejected")
                self._last_signature = signature
                self._last_plan = plan
                return plan
            plan = RAGQueryPlan(query, source="llm", rationale=str(response.get("rationale") or ""))
            self._last_signature = signature
            self._last_plan = plan
            return plan
        except Exception:
            plan = RAGQueryPlan(fallback, source="deterministic", rationale="llm query failed")
            self._last_signature = signature
            self._last_plan = plan
            return plan

    @staticmethod
    def _deterministic_query(
        observation: dict[str, Any],
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
    ) -> str:
        gaps = report_gaps(report_tracker.values)
        entities = []
        for kind in ("host", "user", "domain", "target"):
            entities.extend(registry.best_entities(kind)[:2])
        parts = [
            "soc incident response evidence",
            str(observation.get("attacker_state") or "investigation"),
            gap_terms(gaps),
            " ".join(entities),
        ]
        return RAGQueryPlanner._clean_query(" ".join(part for part in parts if part)) or "soc incident response evidence phishing exfiltration containment"

    @staticmethod
    def _state_summary(
        observation: dict[str, Any],
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
    ) -> str:
        supports = [
            {
                "entity": support.entity_value,
                "type": support.entity_type,
                "source": support.source_table,
                "indicators": support.malicious_indicators,
            }
            for support in registry.ranked_supports("host")[:4]
            + registry.ranked_supports("user")[:4]
            + registry.ranked_supports("domain")[:4]
            + registry.ranked_supports("target")[:4]
        ]
        return json.dumps(
            {
                "step_index": observation.get("step_index"),
                "attacker_state": observation.get("attacker_state"),
                "report_values": report_tracker.values,
                "focus": report_focus(report_tracker.values),
                "known_entities": {kind: registry.best_entities(kind)[:5] for kind in ("host", "user", "domain", "target")},
                "ranked_supports": supports,
            },
            sort_keys=True,
        )

    def _planning_signature(
        self,
        observation: dict[str, Any],
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
    ) -> str:
        return json.dumps(
            {
                "attacker_state": observation.get("attacker_state"),
                "focus": report_focus(report_tracker.values),
                "support_count": len(registry.supports),
                "content_count": len(registry.content_ids),
                "seen_count": len(registry.seen_ids),
                "known_entities": {kind: registry.best_entities(kind)[:3] for kind in ("host", "user", "domain", "target")},
            },
            sort_keys=True,
        )

    @staticmethod
    def _clean_query(raw: str) -> str:
        query = re.sub(r"\s+", " ", raw).strip()
        if not query:
            return ""
        lower = query.casefold()
        if any(marker in lower for marker in _INJECTION_MARKERS):
            return ""
        if any(token in lower for token in ("select ", "insert ", "update ", "delete ", "drop ", "--")):
            return ""
        return query[:MAX_RAG_QUERY_CHARS].strip()

