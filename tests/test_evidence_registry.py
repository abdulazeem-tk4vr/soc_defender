from defender.evidence_registry import EvidenceRegistry
from defender.report_readiness import ReportReadinessTracker


def test_process_names_are_not_extracted_as_domains():
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "event_id": "proc-1",
            "host_id": "h-001-01",
            "user_id": "u-001",
            "process": "svchost.exe",
            "command_line": "PROC host=h-001-01 user=u-001 process=svchost.exe cmd=reg_add_runkey",
            "trust_tier": "verified",
        },
        step_seen=4,
    )

    assert "svchost.exe" not in registry.best_entities("domain")


def test_key_value_domain_and_target_support_report_readiness():
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "alert_id": "alert-1",
            "message": 'ALERT type=exfil_attempt message="dst_domain=notifysecure.io src_host=h-001-02 target=t-001"',
            "trust_tier": "verified",
        },
        step_seen=6,
    )
    tracker = ReportReadinessTracker()
    tracker.update(registry)

    assert "notifysecure.io" in registry.best_entities("domain")
    assert tracker.values["attacker_domain"] == "notifysecure.io"
    assert tracker.values["data_target"] == "t-001"
