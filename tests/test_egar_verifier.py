from defender.evidence_registry import EntitySupport, EvidenceRegistry
from defender.prompt_guard import LocalizedSpan
from defender.verifier import gate_containment


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
    assert decision.reason == "support only appears in flagged scanner spans"
