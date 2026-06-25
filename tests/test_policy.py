from defender.policy import DefenderPolicy
from defender.calibration import CalibrationConfig


def test_policy_records_failed_last_emitted_query():
    policy = DefenderPolicy()
    action = policy.sql_planner.action_for_sql("SELECT * FROM alerts ORDER BY step DESC LIMIT 20")

    observation = {
        "step_index": 1,
        "containment": {},
        "last_action_result": {
            "ok": True,
            "message": "query_logs",
            "data": {"ok": False, "error": "no such column: created_at"},
        },
    }
    policy.next_action(observation)

    assert action.params["sql"] in policy.sql_planner.failed_queries


def test_gated_containment_uses_report_tracked_entities_only():
    policy = DefenderPolicy(containment_min_step=1)
    policy.report_tracker.values.update(
        {
            "patient_zero_host": "h-primary",
            "compromised_user": "u-primary",
            "attacker_domain": "unknown",
            "data_target": "unknown",
            "initial_vector": "phish",
        }
    )
    policy.registry.add_row(
        {
            "alert_id": "a-secondary",
            "host_id": "h-secondary",
            "message": "suspicious lateral persistence alert",
            "trust_tier": "trusted",
        },
        step_seen=1,
    )
    policy.registry.add_row(
        {
            "alert_id": "a-primary",
            "host_id": "h-primary",
            "message": "credential persistence alert",
            "trust_tier": "trusted",
        },
        step_seen=1,
    )

    action = policy._next_gated_containment(5, {"isolated_hosts": [], "blocked_domains": [], "reset_users": []})

    assert action.action_type == "isolate_host"
    assert action.params == {"host_id": "h-primary"}


def test_gated_containment_skips_untracked_suspicious_entities():
    policy = DefenderPolicy(containment_min_step=1)
    policy.report_tracker.values.update(
        {
            "patient_zero_host": "unknown",
            "compromised_user": "unknown",
            "attacker_domain": "unknown",
            "data_target": "unknown",
            "initial_vector": "phish",
        }
    )
    policy.registry.add_row(
        {
            "alert_id": "a-secondary",
            "host_id": "h-secondary",
            "message": "suspicious lateral persistence alert",
            "trust_tier": "trusted",
        },
        step_seen=1,
    )

    assert policy._next_gated_containment(5, {"isolated_hosts": [], "blocked_domains": [], "reset_users": []}) is None


def test_policy_derives_containment_min_step_from_max_steps_when_unset():
    calibration = CalibrationConfig()
    short_policy = DefenderPolicy(max_steps=6, calibration=calibration)
    standard_policy = DefenderPolicy(max_steps=15, calibration=calibration)

    assert short_policy.containment_min_step == 2
    assert standard_policy.containment_min_step == 5


def test_policy_uses_calibrated_containment_min_step_by_default():
    calibration = CalibrationConfig(containment_min_step=7)
    policy = DefenderPolicy(calibration=calibration)

    assert policy.containment_min_step == 7
    assert policy.registry.calibration is calibration
    assert policy.report_tracker.calibration is calibration


def test_email_only_domain_can_produce_gated_containment():
    policy = DefenderPolicy(containment_min_step=1)
    policy.registry.add_row(
        {
            "email_id": "email-domain",
            "body": "credential phish dst_domain=evil.example",
            "trust_tier": "verified",
        },
        step_seen=1,
    )
    policy.report_tracker.update(policy.registry)

    action = policy._next_gated_containment(5, {"isolated_hosts": [], "blocked_domains": [], "reset_users": []})

    assert action.action_type == "block_domain"
    assert action.params == {"domain": "evil.example"}
    assert ("block_domain", "evil.example") in policy.attempted_containment


def _add_three_approved_containment_entities(policy):
    policy.report_tracker.values.update(
        {
            "patient_zero_host": "h-001",
            "compromised_user": "u-001",
            "attacker_domain": "evil.example",
            "data_target": "unknown",
            "initial_vector": "phish",
        }
    )
    policy.registry.add_row(
        {
            "alert_id": "alert-host",
            "host_id": "h-001",
            "message": "verified credential alert",
            "trust_tier": "verified",
        },
        step_seen=8,
    )
    policy.registry.add_row(
        {
            "auth_id": "auth-user",
            "user_id": "u-001",
            "message": "verified credential alert",
            "trust_tier": "verified",
        },
        step_seen=8,
    )
    policy.registry.add_row(
        {
            "flow_id": "flow-domain",
            "dst_domain": "evil.example",
            "message": "verified exfil alert",
            "trust_tier": "verified",
        },
        step_seen=8,
    )


def test_policy_prioritizes_containment_when_remaining_slots_match_approved_candidates():
    policy = DefenderPolicy(max_steps=15, containment_min_step=0)
    _add_three_approved_containment_entities(policy)
    containment = {"isolated_hosts": [], "blocked_domains": [], "reset_users": []}

    assert policy.approved_pending_containment_count(10, containment) == 3
    assert policy.should_prioritize_containment(10, containment) is False
    assert policy.should_prioritize_containment(11, containment) is True
    assert policy.should_prioritize_containment(14, containment) is False
