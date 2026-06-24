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
