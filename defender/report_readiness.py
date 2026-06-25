from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .actions import normalize_report
from .calibration import CalibrationConfig, load_calibration
from .evidence_registry import EvidenceRegistry


@dataclass
class ReportFieldState:
    value: str = "unknown"
    confidence: float = 0.0
    provenance: tuple[str, ...] = ()
    conflict_history: list[dict[str, Any]] = field(default_factory=list)
    locked: bool = False


@dataclass
class ReportReadinessTracker:
    calibration: CalibrationConfig = field(default_factory=load_calibration)
    values: dict[str, str] = field(
        default_factory=lambda: {
            "patient_zero_host": "unknown",
            "compromised_user": "unknown",
            "attacker_domain": "unknown",
            "data_target": "unknown",
            "initial_vector": "phish",
        }
    )
    field_state: dict[str, ReportFieldState] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name, value in self.values.items():
            self.field_state.setdefault(
                field_name,
                ReportFieldState(value=value, locked=value != "unknown" and field_name == "initial_vector"),
            )

    def update(self, registry: EvidenceRegistry) -> None:
        host = self._first_with_indicator(
            registry,
            "host",
            "patient_zero_host",
            {"credential", "creds", "phish", "alert", "exfil"},
        )
        user = self._first_with_indicator(
            registry,
            "user",
            "compromised_user",
            {"credential", "creds", "phish", "alert", "exfil"},
        )
        domain = self._first_with_indicator(registry, "domain", "attacker_domain", {"exfil", "phish", "alert"})
        target = self._first_with_indicator(registry, "target", "data_target", {"exfil", "staging", "alert"})
        self._maybe_update("patient_zero_host", host)
        self._maybe_update("compromised_user", user)
        self._maybe_update("attacker_domain", domain)
        self._maybe_update("data_target", target)
        self._record_conflicts(registry, "patient_zero_host", "host")
        self._record_conflicts(registry, "compromised_user", "user")
        self._record_conflicts(registry, "attacker_domain", "domain")
        self._record_conflicts(registry, "data_target", "target")

    def report(self, containment: dict[str, Any]) -> dict[str, Any]:
        payload = dict(self.values)
        payload["containment_actions"] = {
            "isolated_hosts": list(containment.get("isolated_hosts") or []),
            "blocked_domains": list(containment.get("blocked_domains") or []),
            "reset_users": list(containment.get("reset_users") or []),
        }
        return normalize_report(payload)

    def is_complete(self) -> bool:
        return all(self.values.get(field) != "unknown" for field in self.values)

    def _maybe_update(self, report_field: str, candidate: tuple[str, float, tuple[str, ...]] | None) -> None:
        if candidate is None:
            return
        value, confidence, provenance = candidate
        state = self.field_state.setdefault(report_field, ReportFieldState(value=self.values.get(report_field, "unknown")))
        if state.locked and value != state.value and confidence <= state.confidence:
            state.conflict_history.append(
                {"rejected": value, "confidence": confidence, "provenance": provenance, "kept": state.value}
            )
            return
        if state.value not in {"unknown", value} and confidence <= state.confidence:
            state.conflict_history.append(
                {"rejected": value, "confidence": confidence, "provenance": provenance, "kept": state.value}
            )
            return
        if state.value not in {"unknown", value}:
            state.conflict_history.append(
                {"replaced": state.value, "confidence": state.confidence, "provenance": state.provenance, "with": value}
            )
        state.value = value
        state.confidence = confidence
        state.provenance = provenance
        state.locked = confidence >= self.calibration.report_field_threshold(report_field) + 2.0
        self.values[report_field] = value

    def _record_conflicts(self, registry: EvidenceRegistry, report_field: str, entity_type: str) -> None:
        state = self.field_state.setdefault(report_field, ReportFieldState(value=self.values.get(report_field, "unknown")))
        if state.value == "unknown":
            return
        threshold = self.calibration.report_field_threshold(report_field)
        known_rejections = {
            (item.get("rejected"), tuple(item.get("provenance", ())))
            for item in state.conflict_history
            if "rejected" in item
        }
        for candidate in registry.scored_candidates(entity_type):
            if not candidate.eligible or candidate.score < threshold or candidate.entity_value == state.value:
                continue
            marker = (candidate.entity_value, candidate.evidence_ids)
            if marker in known_rejections:
                continue
            state.conflict_history.append(
                {
                    "rejected": candidate.entity_value,
                    "confidence": candidate.score,
                    "provenance": candidate.evidence_ids,
                    "kept": state.value,
                }
            )

    def _first_with_indicator(
        self,
        registry: EvidenceRegistry,
        entity_type: str,
        report_field: str,
        preferred: set[str],
    ) -> tuple[str, float, tuple[str, ...]] | None:
        fallback = None
        threshold = self.calibration.report_field_threshold(report_field)
        for candidate in registry.scored_candidates(entity_type):
            if not candidate.eligible or candidate.score < threshold:
                continue
            support = candidate.support[0] if candidate.support else None
            indicators = set().union(*(set(item.malicious_indicators) for item in candidate.support))
            if fallback is None:
                fallback = (candidate.entity_value, candidate.score, candidate.evidence_ids)
            if support and preferred.intersection(indicators):
                return (candidate.entity_value, candidate.score, candidate.evidence_ids)
        return fallback
