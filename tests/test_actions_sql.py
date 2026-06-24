from defender.actions import normalize_report, query_logs, validate_action
from defender.sql_planner import SQLPlanner, is_safe_select


def test_query_logs_rejects_non_evidence_tables_and_select_one():
    for sql in (
        "SELECT 1",
        "SELECT * FROM attacker_decisions LIMIT 1",
        "SELECT * FROM alerts; DROP TABLE alerts",
        "DELETE FROM alerts",
    ):
        ok, reason = validate_action(query_logs(sql))
        assert not ok, reason


def test_query_logs_accepts_known_evidence_tables():
    ok, reason = validate_action(query_logs("SELECT * FROM alerts ORDER BY step DESC LIMIT 20"))
    assert ok, reason


def test_sql_planner_repairs_unsafe_or_repeated_queries():
    planner = SQLPlanner()
    first = planner.action_for_sql("SELECT * FROM alerts ORDER BY step DESC LIMIT 20")
    second = planner.action_for_sql("SELECT * FROM alerts ORDER BY step DESC LIMIT 20")
    unsafe = planner.action_for_sql("SELECT * FROM prompt_injections LIMIT 20")

    assert first.params["sql"] == "SELECT * FROM alerts ORDER BY step DESC LIMIT 20"
    assert second.params["sql"] == "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20"
    assert unsafe.params["sql"] == "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20"
    assert is_safe_select(unsafe.params["sql"])


def test_sql_planner_entity_queries_use_step_ordering():
    planner = SQLPlanner()
    action = planner.query_for_entity("h-001-01", "host")

    assert "ORDER BY step DESC" in action.params["sql"]
    assert "created_at" not in action.params["sql"]


def test_report_validation_requires_containment_lists():
    report = normalize_report({"patient_zero_host": "h-1"})
    ok, reason = validate_action(type("Action", (), {"action_type": "submit_report", "params": {"summary_json": report}})())
    assert ok, reason

    report["containment_actions"]["blocked_domains"] = "evil.example"
    ok, reason = validate_action(type("Action", (), {"action_type": "submit_report", "params": {"summary_json": report}})())
    assert not ok
    assert "blocked_domains" in reason
