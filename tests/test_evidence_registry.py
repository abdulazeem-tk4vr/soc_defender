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


def test_registry_extracts_open_sec_compiled_domain_and_target_rows():
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "alert_id": "alert-seed-001-5",
            "message": "ALERT type=exfil_attempt severity=critical stage=exfiltration message=\"dst_domain=notifysecure.io src_host=h-001-02\"",
            "trust_tier": "verified",
            "source": "alerting",
        },
        step_seen=5,
    )
    registry.add_row(
        {
            "event_id": "proc-seed-001-3",
            "host_id": "h-001-02",
            "user_id": "u-001",
            "process_name": "zip.exe",
            "command_line": "PROC host=h-001-02 user=u-001 process=zip.exe cmd=stage target=t-001",
            "trust_tier": "verified",
            "source": "telemetry",
        },
        step_seen=3,
    )
    tracker = ReportReadinessTracker()
    tracker.update(registry)

    assert registry.best_entities("domain") == ["notifysecure.io"]
    assert registry.best_entities("target") == ["t-001"]
    assert tracker.values["attacker_domain"] == "notifysecure.io"
    assert tracker.values["data_target"] == "t-001"
