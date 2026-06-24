from __future__ import annotations

from dataclasses import dataclass

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


def gate_containment(
    action_type: str,
    entity_value: str,
    registry: EvidenceRegistry,
    step_index: int,
    containment_min_step: int = 3,
) -> GateDecision:
    entity_type = CONTAINMENT_ENTITY.get(action_type)
    if entity_type is None:
        return GateDecision(False, "not a containment action")
    if step_index < containment_min_step:
        return GateDecision(False, "containment before configured minimum step")
    supports = tuple(registry.support_for(entity_value, entity_type))
    if not supports:
        return GateDecision(False, "exact entity not observed in evidence")
    trusted = tuple(s for s in supports if s.trusted and s.content_exposed)
    if not trusted:
        return GateDecision(False, "no trusted content-exposed support")
    malicious = tuple(s for s in trusted if s.malicious_indicators)
    if not malicious:
        return GateDecision(False, "support does not imply malicious behavior")
    if all(s.scanner_status in {"flagged", "localized"} for s in malicious):
        return GateDecision(False, "support only appears in flagged scanner spans")
    return GateDecision(True, "approved", malicious)
