from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .actions import normalize_report
from .evidence_registry import EvidenceRegistry


@dataclass
class ReportReadinessTracker:
    values: dict[str, str] = field(
        default_factory=lambda: {
            "patient_zero_host": "unknown",
            "compromised_user": "unknown",
            "attacker_domain": "unknown",
            "data_target": "unknown",
            "initial_vector": "phish",
        }
    )

    def update(self, registry: EvidenceRegistry) -> None:
        host = self._first_with_indicator(registry, "host", {"credential", "creds", "phish", "alert", "exfil"})
        user = self._first_with_indicator(registry, "user", {"credential", "creds", "phish", "alert", "exfil"})
        domain = self._first_with_indicator(registry, "domain", {"exfil", "phish", "alert"})
        target = self._first_with_indicator(registry, "target", {"exfil", "staging", "alert"})
        if host:
            self.values["patient_zero_host"] = host
        if user:
            self.values["compromised_user"] = user
        if domain:
            self.values["attacker_domain"] = domain
        if target:
            self.values["data_target"] = target

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

    @staticmethod
    def _first_with_indicator(registry: EvidenceRegistry, entity_type: str, preferred: set[str]) -> str | None:
        fallback = None
        for support in registry.supports:
            if support.entity_type != entity_type or not support.trusted or not support.content_exposed:
                continue
            if fallback is None:
                fallback = support.entity_value
            if preferred.intersection(support.malicious_indicators):
                return support.entity_value
        return fallback
