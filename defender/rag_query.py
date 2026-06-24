from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .evidence_registry import EvidenceRegistry
from .llm import LLMClient
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

    def plan(
        self,
        observation: dict[str, Any],
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
    ) -> RAGQueryPlan:
        fallback = self._deterministic_query(observation, registry, report_tracker)
        if self.llm is None:
            return RAGQueryPlan(fallback, source="deterministic", rationale="no llm configured")
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
                return RAGQueryPlan(fallback, source="deterministic", rationale="llm query rejected")
            return RAGQueryPlan(query, source="llm", rationale=str(response.get("rationale") or ""))
        except Exception:
            return RAGQueryPlan(fallback, source="deterministic", rationale="llm query failed")

    @staticmethod
    def _deterministic_query(
        observation: dict[str, Any],
        registry: EvidenceRegistry,
        report_tracker: ReportReadinessTracker,
    ) -> str:
        gaps = [key for key, value in report_tracker.values.items() if value == "unknown"]
        entities = []
        for kind in ("host", "user", "domain", "target"):
            entities.extend(registry.best_entities(kind)[:2])
        parts = [
            "soc incident response evidence",
            str(observation.get("attacker_state") or "investigation"),
            _gap_terms(gaps),
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
                "unknown_report_fields": [key for key, value in report_tracker.values.items() if value == "unknown"],
                "known_entities": {kind: registry.best_entities(kind)[:5] for kind in ("host", "user", "domain", "target")},
                "ranked_supports": supports,
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


def _gap_terms(gaps: list[str]) -> str:
    terms = []
    if "attacker_domain" in gaps:
        terms.append("identify attacker domain phishing email headers netflow dst_domain exfiltration")
    if "data_target" in gaps:
        terms.append("identify data target staging exfiltration process_events file access")
    if "patient_zero_host" in gaps:
        terms.append("identify patient zero host credential theft authentication alerts")
    if "compromised_user" in gaps:
        terms.append("identify compromised user phishing credential reuse authentication")
    if not terms:
        terms.append("containment evidence isolate host reset user block domain")
    return " ".join(terms)
