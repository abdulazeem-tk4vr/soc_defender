from defender.policy import DefenderPolicy


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
