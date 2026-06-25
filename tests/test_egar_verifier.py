from defender.evidence_registry import EntitySupport, EvidenceRegistry
from defender.prompt_guard import LocalizedSpan
from defender.verifier import gate_containment
from defender.calibration import CalibrationConfig


def test_gate_rejects_unobserved_containment_entity():
    decision = gate_containment("isolate_host", "h-404", EvidenceRegistry(), step_index=8, containment_min_step=5)

    assert decision.approved is False
    assert decision.reason == "exact entity not observed in evidence"


def test_gate_rejects_support_only_from_localized_injection_span():
    registry = EvidenceRegistry()
    registry.supports.append(
        EntitySupport(
            entity_value="evil.example",
            entity_type="domain",
            evidence_id="alert-1",
            source_table="alerts",
            trust_tier="verified",
            source=None,
            injection_id="inj-1",
            content_exposed=True,
            step_seen=6,
            malicious_indicators=("exfil",),
            scanner_status="suspicious",
            localized_spans=(LocalizedSpan(0, 20, "instruction_override", 0.9),),
        )
    )

    decision = gate_containment("block_domain", "evil.example", registry, step_index=8, containment_min_step=5)

    assert decision.approved is False
    assert decision.reason == "no trusted untainted content-exposed support"


def test_gate_rejects_when_score_is_below_action_threshold():
    calibration = CalibrationConfig(containment_thresholds={"block_domain": 50.0})
    registry = EvidenceRegistry(calibration=calibration)
    registry.add_row(
        {
            "flow_id": "flow-1",
            "dst_domain": "evil.example",
            "message": "exfil alert",
            "trust_tier": "verified",
        },
        step_seen=6,
    )

    decision = gate_containment(
        "block_domain",
        "evil.example",
        registry,
        step_index=8,
        containment_min_step=5,
        calibration=calibration,
    )

    assert decision.approved is False
    assert decision.reason == "support score below containment threshold"
    assert decision.score < decision.threshold


def test_gate_rejects_action_entity_mismatch():
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "flow_id": "flow-1",
            "dst_domain": "evil.example",
            "message": "exfil alert",
            "trust_tier": "verified",
        },
        step_seen=6,
    )

    decision = gate_containment("isolate_host", "evil.example", registry, step_index=8, containment_min_step=5)

    assert decision.approved is False
    assert decision.reason == "action/entity mismatch"
