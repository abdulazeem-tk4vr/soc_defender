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
    score: float = 0.0
    threshold: float = 0.0
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
    if step_index < containment_min_step:
        return GateDecision(False, "containment before configured minimum step")
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
            score=candidate.score,
            threshold=calibration.containment_threshold(action_type),
            evidence_ids=candidate.evidence_ids,
        )
    malicious = tuple(s for s in candidate.support if s.malicious_indicators)
    if not malicious:
        return GateDecision(
            False,
            "support does not imply malicious behavior",
            candidate.support,
            score=candidate.score,
            threshold=calibration.containment_threshold(action_type),
            evidence_ids=candidate.evidence_ids,
        )
    if action_type == "block_domain" and not any(s.source_table in {"netflow", "alerts"} for s in malicious):
        return GateDecision(
            False,
            "domain lacks trusted network or alert malicious support",
            malicious,
            score=candidate.score,
            threshold=calibration.containment_threshold(action_type),
            evidence_ids=candidate.evidence_ids,
        )
    threshold = calibration.containment_threshold(action_type)
    if candidate.score < threshold:
        return GateDecision(
            False,
            "support score below containment threshold",
            malicious,
            score=candidate.score,
            threshold=threshold,
            evidence_ids=candidate.evidence_ids,
        )
    return GateDecision(True, "approved", malicious, score=candidate.score, threshold=threshold, evidence_ids=candidate.evidence_ids)
