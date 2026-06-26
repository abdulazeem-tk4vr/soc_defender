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


def test_report_readiness_extracts_alert_domain_and_process_target():
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "alert_id": "alert-1",
            "message": "ALERT type=exfil_attempt stage=exfiltration dst_domain=notifysecure.io src_host=h-001-02",
            "trust_tier": "verified",
            "source": "alerting",
        },
        step_seen=4,
    )
    registry.add_row(
        {
            "event_id": "proc-1",
            "message": "PROC host=h-001-02 user=u-001 process=tool.exe cmd=api_export target=t-001",
            "trust_tier": "verified",
            "source": "telemetry",
        },
        step_seen=3,
    )
    tracker = ReportReadinessTracker()

    tracker.update(registry)

    assert tracker.values["attacker_domain"] == "notifysecure.io"
    assert tracker.values["data_target"] == "t-001"
