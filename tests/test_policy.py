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
