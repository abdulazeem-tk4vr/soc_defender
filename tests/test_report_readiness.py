from defender.evidence_registry import EvidenceRegistry
from defender.report_readiness import ReportReadinessTracker


def test_report_readiness_prefers_ranked_domain_support():
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "email_id": "email-1",
            "body": "newsletter link benign.example",
            "trust_tier": "verified",
        },
        step_seen=1,
    )
    registry.add_row(
        {
            "flow_id": "flow-1",
            "dst_domain": "evil.example",
            "message": "exfil bytes to evil.example",
            "trust_tier": "verified",
        },
        step_seen=2,
    )
    tracker = ReportReadinessTracker()

    tracker.update(registry)

    assert registry.best_entities("domain")[0] == "evil.example"
    assert tracker.values["attacker_domain"] == "evil.example"


def test_report_readiness_keeps_stronger_locked_value_over_weaker_later_conflict():
    registry = EvidenceRegistry()
    tracker = ReportReadinessTracker()
    registry.add_row(
        {
            "flow_id": "flow-strong",
            "dst_domain": "evil.example",
            "message": "exfil alert to evil.example",
            "trust_tier": "verified",
        },
        step_seen=2,
    )
    tracker.update(registry)

    registry.add_row(
        {
            "email_id": "email-weak",
            "body": "credential phish dst_domain=decoy.example",
            "trust_tier": "trusted",
        },
        step_seen=5,
    )
    tracker.update(registry)

    assert tracker.values["attacker_domain"] == "evil.example"
    assert tracker.field_state["attacker_domain"].locked
    assert tracker.field_state["attacker_domain"].provenance == ("flow-strong",)
    assert tracker.field_state["attacker_domain"].conflict_history



def test_verifier_choice_can_override_existing_report_value_when_evidence_backed():
    from defender.evidence_registry import EvidenceRegistry

    tracker = ReportReadinessTracker()
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "alert_id": "alert-initial",
            "host_id": "h-001",
            "message": "credential alert stage",
            "trust_tier": "trusted",
        },
        step_seen=1,
    )
    tracker.update(registry)

    registry.add_row(
        {
            "alert_id": "alert-late",
            "host_id": "h-002",
            "message": "exfil alert stage",
            "trust_tier": "trusted",
        },
        step_seen=10,
    )
    tracker.update(registry)
    result = tracker.apply_verified_choices(registry, {"patient_zero_host": "h-002"})

    assert result["accepted"] == {"patient_zero_host": "h-002"}
    assert tracker.values["patient_zero_host"] == "h-002"
