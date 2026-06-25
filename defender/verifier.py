from __future__ import annotations

from dataclasses import dataclass

from .calibration import CalibrationConfig, load_calibration
from .evidence_registry import EvidenceRegistry, EntitySupport


CONTAINMENT_ENTITY = {
    "isolate_host": "host",
    "block_domain": "domain",
    "reset_user": "user",
}


@dataclass(frozen=True)
class GateDecision:
    approved: bool
    reason: str
    support: tuple[EntitySupport, ...] = ()
    evidence_ids: tuple[str, ...] = ()


def gate_containment(
    action_type: str,
    entity_value: str,
    registry: EvidenceRegistry,
    step_index: int,
    containment_min_step: int = 3,
    calibration: CalibrationConfig | None = None,
) -> GateDecision:
    calibration = calibration or getattr(registry, "calibration", None) or load_calibration()
    entity_type = CONTAINMENT_ENTITY.get(action_type)
    if entity_type is None:
        return GateDecision(False, "not a containment action")

    candidate = registry.scored_candidate(entity_value, entity_type)
    if candidate is None:
        if registry.support_for(entity_value):
            return GateDecision(False, "action/entity mismatch")
        return GateDecision(False, "exact entity not observed in evidence")

    if candidate.blocked_reasons:
        if "scanner-flagged-only support" in candidate.blocked_reasons:
            reason = "no trusted untainted content-exposed support"
        elif "untrusted-only support" in candidate.blocked_reasons:
            reason = "no trusted untainted content-exposed support"
        elif "no content-exposed support" in candidate.blocked_reasons:
            reason = "no content-exposed support"
        else:
            reason = candidate.blocked_reasons[0]
        return GateDecision(
            False,
            reason,
            candidate.support,
            evidence_ids=candidate.evidence_ids,
        )

    if step_index < containment_min_step:
        return GateDecision(
            False,
            "containment before configured minimum step",
            candidate.support,
            evidence_ids=candidate.evidence_ids,
        )

    return GateDecision(True, "approved", candidate.support, evidence_ids=candidate.evidence_ids)
