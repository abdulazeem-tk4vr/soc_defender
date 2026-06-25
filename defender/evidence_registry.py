from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .calibration import CalibrationConfig, load_calibration
from .scanner import InjectionScanner

HOST_RE = re.compile(r"\bh-[A-Za-z0-9_.-]+\b")
USER_RE = re.compile(r"\bu-[A-Za-z0-9_.-]+\b")
TARGET_RE = re.compile(r"\bt-[A-Za-z0-9_.-]+\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
DOMAIN_KV_RE = re.compile(
    r"\b(?:dst_domain|destination_domain|dest_domain|domain|attacker_domain|destination)=([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
    re.I,
)
TARGET_KV_RE = re.compile(
    r"\b(?:target|target_id|data_target|dataset|object|object_id|resource|resource_id)=([A-Za-z0-9_.:-]+)\b",
    re.I,
)

MALICIOUS_WORDS = {
    "phish",
    "credential",
    "creds",
    "password",
    "exfil",
    "malware",
    "lateral",
    "persistence",
    "stage",
    "staging",
    "suspicious",
    "alert",
    "failed",
    "success",
}


@dataclass(frozen=True)
class EntitySupport:
    entity_value: str
    entity_type: str
    evidence_id: str
    source_table: str
    trust_tier: str | None
    source: str | None
    injection_id: str | None
    content_exposed: bool
    step_seen: int
    supporting_fields: tuple[str, ...] = ()
    malicious_indicators: tuple[str, ...] = ()
    scanner_status: str = "unknown"
    localized_spans: tuple[Any, ...] = ()

    @property
    def trusted(self) -> bool:
        return self.trust_tier != "untrusted"

    @property
    def tainted(self) -> bool:
        return self.scanner_status in {"flagged", "suspicious", "localized"} or bool(self.localized_spans)

    @property
    def trusted_action_support(self) -> bool:
        return self.trusted and self.content_exposed and not self.tainted


@dataclass(frozen=True)
class ScoredEntityCandidate:
    entity_value: str
    entity_type: str
    score: float
    evidence_ids: tuple[str, ...]
    support: tuple[EntitySupport, ...]
    blocked_reasons: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return not self.blocked_reasons


def _text_from_row(row: dict[str, Any]) -> str:
    return " ".join(str(v) for v in row.values() if v is not None)


def _indicators(text: str) -> tuple[str, ...]:
    lower = text.lower()
    found = sorted(word for word in MALICIOUS_WORDS if word in lower)
    return tuple(found)


def _entity_id(row: dict[str, Any], table: str) -> str:
    for key in ("email_id", "alert_id", "auth_id", "flow_id", "event_id"):
        if row.get(key):
            return str(row[key])
    return f"{table}:{abs(hash(_text_from_row(row)))}"


def _source_table(row: dict[str, Any], default: str = "unknown") -> str:
    if "email_id" in row:
        return "email_logs"
    if "alert_id" in row:
        return "alerts"
    if "auth_id" in row:
        return "auth_logs"
    if "flow_id" in row:
        return "netflow"
    if "event_id" in row:
        return "process_events"
    return default


def _extract_entities(row: dict[str, Any]) -> list[tuple[str, str, tuple[str, ...]]]:
    values: dict[tuple[str, str], set[str]] = {}
    for field, raw_value in row.items():
        text = "" if raw_value is None else str(raw_value)
        candidates: list[tuple[str, str]] = []
        if field in {"host_id", "src_host", "dst_host", "host"}:
            candidates.append((text, "host"))
        if field in {"user_id", "user", "recipient", "compromised_user"}:
            if text.startswith("u-"):
                candidates.append((text, "user"))
        if field in {"dst_domain", "destination_domain", "dest_domain", "domain", "attacker_domain", "destination"}:
            candidates.append((text, "domain"))
        if field in {"target_id", "data_target", "target", "object_id", "resource_id", "dataset", "file_id"}:
            candidates.append((text, "target"))
        candidates.extend((match.group(0), "host") for match in HOST_RE.finditer(text))
        candidates.extend((match.group(0), "user") for match in USER_RE.finditer(text))
        candidates.extend((match.group(0), "target") for match in TARGET_RE.finditer(text))
        candidates.extend((match.group(1), "domain") for match in DOMAIN_KV_RE.finditer(text))
        candidates.extend((match.group(1), "target") for match in TARGET_KV_RE.finditer(text))
        for value, entity_type in candidates:
            value = value.strip().strip('",')
            if not value or value == ".":
                continue
            values.setdefault((value, entity_type), set()).add(field)
    return [(value, entity_type, tuple(sorted(fields))) for (value, entity_type), fields in values.items()]


@dataclass
class EvidenceRegistry:
    supports: list[EntitySupport] = field(default_factory=list)
    content_ids: set[str] = field(default_factory=set)
    seen_ids: set[str] = field(default_factory=set)
    scanner: InjectionScanner = field(default_factory=InjectionScanner)
    calibration: CalibrationConfig = field(default_factory=load_calibration)

    def update_from_observation(self, observation: Any) -> None:
        self.content_ids.update(getattr(observation, "evidence_content_ids", set()))
        self.seen_ids.update(getattr(observation, "evidence_seen_ids", set()))
        result = getattr(observation, "last_action_result", {}) or {}
        data = result.get("data") or {}
        if not data:
            return
        if isinstance(data.get("rows"), list):
            for row in data["rows"]:
                self.add_row(dict(row), step_seen=observation.step_index)
        if isinstance(data.get("email"), dict):
            self.add_row(dict(data["email"]), step_seen=observation.step_index)
        if isinstance(data.get("alert"), dict):
            row = dict(data["alert"])
            parsed = data.get("parsed")
            if isinstance(parsed, dict):
                row.update(parsed)
            self.add_row(row, step_seen=observation.step_index)

    def add_row(self, row: dict[str, Any], step_seen: int) -> None:
        table = _source_table(row)
        evidence_id = _entity_id(row, table)
        self.content_ids.add(evidence_id)
        text = _text_from_row(row)
        indicators = _indicators(text)
        scan = self.scanner.scan_evidence_row(row)
        for value, entity_type, fields in _extract_entities(row):
            support = EntitySupport(
                entity_value=value,
                entity_type=entity_type,
                evidence_id=evidence_id,
                source_table=table,
                trust_tier=row.get("trust_tier"),
                source=row.get("source"),
                injection_id=row.get("injection_id"),
                content_exposed=True,
                step_seen=step_seen,
                supporting_fields=fields,
                malicious_indicators=indicators,
                scanner_status=scan.status,
                localized_spans=scan.localized_spans,
            )
            if support not in self.supports:
                self.supports.append(support)

    def support_for(self, entity_value: str, entity_type: str | None = None) -> list[EntitySupport]:
        return [
            support
            for support in self.supports
            if support.entity_value == entity_value and (entity_type is None or support.entity_type == entity_type)
        ]

    def trusted_support_for(self, entity_value: str, entity_type: str | None = None) -> list[EntitySupport]:
        return [support for support in self.support_for(entity_value, entity_type) if support.trusted_action_support]

    def best_entities(self, entity_type: str) -> list[str]:
        seen: list[str] = []
        for candidate in self.scored_candidates(entity_type):
            if candidate.eligible and candidate.entity_value not in seen:
                seen.append(candidate.entity_value)
        return seen

    def ranked_supports(self, entity_type: str) -> list[EntitySupport]:
        scored_supports: list[tuple[float, EntitySupport]] = []
        for support in self.supports:
            if support.entity_type == entity_type and support.trusted_action_support:
                scored_supports.append((self.score_support(support), support))
        return [support for _, support in sorted(scored_supports, key=lambda item: item[0], reverse=True)]

    def scored_candidate(self, entity_value: str, entity_type: str) -> ScoredEntityCandidate | None:
        support = tuple(self.support_for(entity_value, entity_type))
        if not support:
            return None
        return self._candidate_from_support(entity_value, entity_type, support)

    def scored_candidates(self, entity_type: str) -> list[ScoredEntityCandidate]:
        grouped: dict[str, list[EntitySupport]] = {}
        for support in self.supports:
            if support.entity_type == entity_type:
                grouped.setdefault(support.entity_value, []).append(support)
        candidates = [
            self._candidate_from_support(entity_value, entity_type, tuple(support))
            for entity_value, support in grouped.items()
        ]
        return sorted(candidates, key=lambda candidate: candidate.score, reverse=True)

    def _candidate_from_support(
        self,
        entity_value: str,
        entity_type: str,
        support: tuple[EntitySupport, ...],
    ) -> ScoredEntityCandidate:
        trusted = tuple(item for item in support if item.trusted)
        content_exposed = tuple(item for item in trusted if item.content_exposed)
        untainted = tuple(item for item in content_exposed if not self.is_tainted_for_action(item))
        blocked: list[str] = []
        if not support:
            blocked.append("no exact entity support")
        if not content_exposed:
            blocked.append("no content-exposed support")
        if not trusted:
            blocked.append("untrusted-only support")
        if content_exposed and not untainted:
            blocked.append("scanner-flagged-only support")
        eligible_support = untainted
        base_score = sum(self.score_support(item) for item in eligible_support)
        score = base_score + self._corroboration_bonus(eligible_support)
        evidence_ids = tuple(sorted({item.evidence_id for item in eligible_support}))
        return ScoredEntityCandidate(
            entity_value=entity_value,
            entity_type=entity_type,
            score=round(score, 3),
            evidence_ids=evidence_ids,
            support=eligible_support,
            blocked_reasons=tuple(blocked),
        )

    def is_tainted_for_action(self, support: EntitySupport) -> bool:
        if support.scanner_status in self.calibration.taint_reject_statuses:
            return True
        return self.calibration.reject_localized_spans and bool(support.localized_spans)

    def score_support(self, support: EntitySupport) -> float:
        weights = self.calibration.score_weights
        trust_key = support.trust_tier or "unknown"
        trust_score = float(weights["trust_tier"].get(trust_key, weights["trust_tier"].get("unknown", 0.0)))
        table_weights = weights["source_table"].get(support.entity_type, {})
        source_score = float(table_weights.get(support.source_table, weights["source_table"].get("default", 0.0)))
        field_weights = weights["supporting_field"]
        field_score = sum(float(field_weights.get(field, field_weights.get("default", 0.0))) for field in support.supporting_fields)
        field_score = min(3.0, field_score)
        indicator_score = min(4.5, len(support.malicious_indicators) * float(weights["malicious_indicator"]))
        scanner_score = float(weights["scanner_status"].get(support.scanner_status, 0.0))
        recency_score = self._recency_bonus(support)
        return max(0.0, trust_score + source_score + field_score + indicator_score + scanner_score + recency_score)

    def _recency_bonus(self, support: EntitySupport) -> float:
        weights = self.calibration.score_weights["recency"]
        max_step = max((item.step_seen for item in self.supports), default=support.step_seen)
        age = max(0, max_step - support.step_seen)
        window = max(1, int(weights.get("window_steps", 5)))
        if age >= window:
            return 0.0
        return float(weights.get("max_bonus", 1.0)) * ((window - age) / window)

    def _corroboration_bonus(self, support: tuple[EntitySupport, ...]) -> float:
        if len(support) <= 1:
            return 0.0
        weights = self.calibration.score_weights["corroboration"]
        sources = {(item.source_table, item.evidence_id) for item in support}
        source_tables = {item.source_table for item in support}
        bonus = max(0, len(source_tables) - 1) * float(weights.get("per_extra_source", 1.5))
        bonus += max(0, len(sources) - 1) * float(weights.get("per_extra_evidence", 0.5))
        return min(float(weights.get("max_bonus", 3.0)), bonus)
