from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedObservation:
    scenario_id: str = ""
    step_index: int = 0
    attacker_state: str = ""
    new_emails: list[str] = field(default_factory=list)
    new_alerts: list[str] = field(default_factory=list)
    evidence_seen_ids: set[str] = field(default_factory=set)
    evidence_content_ids: set[str] = field(default_factory=set)
    containment: dict[str, list[str]] = field(default_factory=dict)
    last_action_result: dict[str, Any] = field(default_factory=dict)
    done: bool = False


def parse_observation(observation: dict[str, Any]) -> ParsedObservation:
    containment = observation.get("containment") or {}
    if hasattr(containment, "model_dump"):
        containment = containment.model_dump()
    last_result = observation.get("last_action_result") or {}
    if hasattr(last_result, "model_dump"):
        last_result = last_result.model_dump()
    return ParsedObservation(
        scenario_id=str(observation.get("scenario_id") or ""),
        step_index=int(observation.get("step_index") or 0),
        attacker_state=str(observation.get("attacker_state") or ""),
        new_emails=list(observation.get("new_emails") or []),
        new_alerts=list(observation.get("new_alerts") or []),
        evidence_seen_ids=set(observation.get("evidence_seen_ids") or []),
        evidence_content_ids=set(observation.get("evidence_content_ids") or []),
        containment={
            "isolated_hosts": list(containment.get("isolated_hosts") or []),
            "blocked_domains": list(containment.get("blocked_domains") or []),
            "reset_users": list(containment.get("reset_users") or []),
        },
        last_action_result=dict(last_result),
        done=bool(observation.get("done", False)),
    )
