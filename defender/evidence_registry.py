from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .scanner import InjectionScanner

HOST_RE = re.compile(r"\bh-[A-Za-z0-9_.-]+\b")
USER_RE = re.compile(r"\bu-[A-Za-z0-9_.-]+\b")
TARGET_RE = re.compile(r"\bt-[A-Za-z0-9_.-]+\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
DOMAIN_KV_RE = re.compile(r"\b(?:dst_domain|destination_domain|domain)=([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", re.I)

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
        if field in {"dst_domain", "destination_domain", "domain", "attacker_domain"}:
            candidates.append((text, "domain"))
        if field in {"target_id", "data_target"}:
            candidates.append((text, "target"))
        candidates.extend((match.group(0), "host") for match in HOST_RE.finditer(text))
        candidates.extend((match.group(0), "user") for match in USER_RE.finditer(text))
        candidates.extend((match.group(0), "target") for match in TARGET_RE.finditer(text))
        candidates.extend((match.group(1), "domain") for match in DOMAIN_KV_RE.finditer(text))
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
        for support in self.ranked_supports(entity_type):
            if support.entity_value not in seen:
                seen.append(support.entity_value)
        return seen

    def ranked_supports(self, entity_type: str) -> list[EntitySupport]:
        supports = [
            support
            for support in self.supports
            if support.entity_type == entity_type and support.trusted_action_support
        ]
        return sorted(supports, key=self._support_rank, reverse=True)

    @staticmethod
    def _support_rank(support: EntitySupport) -> tuple[int, int, int, int]:
        trust_score = {"verified": 3, "trusted": 2, None: 1}.get(support.trust_tier, 1)
        source_score = {
            ("domain", "netflow"): 5,
            ("target", "process_events"): 5,
            ("target", "alerts"): 4,
            ("host", "alerts"): 4,
            ("host", "auth_logs"): 3,
            ("user", "auth_logs"): 4,
            ("user", "email_logs"): 3,
            ("domain", "alerts"): 3,
            ("domain", "email_logs"): 2,
        }.get((support.entity_type, support.source_table), 1)
        indicator_score = min(5, len(support.malicious_indicators))
        field_score = min(3, len(support.supporting_fields))
        return (trust_score, source_score, indicator_score, field_score)
