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


def test_sql_planner_gap_directed_queries_and_repeat_rotation():
    planner = SQLPlanner()

    first = planner.action_for_sql(planner.next_broad_query({"attacker_domain"}))
    second = planner.action_for_sql(planner.next_broad_query({"attacker_domain"}))

    assert first.params["sql"] == "SELECT DISTINCT dst_domain, COUNT(*) as cnt FROM netflow WHERE dst_domain IS NOT NULL GROUP BY dst_domain ORDER BY cnt DESC LIMIT 20"
    assert second.params["sql"] == "SELECT sender, subject, body FROM email_logs WHERE is_phish = 1 ORDER BY step DESC LIMIT 20"

    for _ in range(6):
        planner.action_for_sql(planner.next_broad_query({"attacker_domain"}))

    assert planner.emitted_counts["SELECT * FROM netflow ORDER BY step DESC LIMIT 20"] <= 2


def test_sql_planner_rejects_unknown_columns_and_uses_gap_fallback():
    planner = SQLPlanner()

    action = planner.action_for_sql(
        "SELECT dst_domain, bytes FROM netflow WHERE src_host = 'h-161-01' ORDER BY step DESC LIMIT 20",
        {"attacker_domain"},
    )

    assert action.params["sql"] == "SELECT DISTINCT dst_domain, COUNT(*) as cnt FROM netflow WHERE dst_domain IS NOT NULL GROUP BY dst_domain ORDER BY cnt DESC LIMIT 20"


def test_sql_planner_accepts_known_netflow_columns_and_count_alias():
    planner = SQLPlanner()

    assert planner.is_schema_valid("SELECT dst_domain, bytes_sent FROM netflow ORDER BY step DESC LIMIT 20")
    assert planner.is_schema_valid("SELECT DISTINCT dst_domain, COUNT(*) as cnt FROM netflow WHERE dst_domain IS NOT NULL GROUP BY dst_domain ORDER BY cnt DESC LIMIT 20")
    assert not planner.is_schema_valid("SELECT dst_domain, bytes FROM netflow ORDER BY step DESC LIMIT 20")


def test_sql_planner_target_and_domain_fallback_queries_use_real_columns():
    planner = SQLPlanner()
    domain_action = planner.query_for_entity("supportlogin.io", "domain")
    planner.record_failure(domain_action.params["sql"])
    fallback_domain = planner.query_for_entity("supportlogin.io", "domain")
    target_action = planner.query_for_entity("t-161", "target")

    assert domain_action.params["sql"] == "SELECT * FROM netflow WHERE dst_domain = 'supportlogin.io' ORDER BY step DESC LIMIT 20"
    assert fallback_domain.params["sql"] == "SELECT sender, subject, body FROM email_logs WHERE sender LIKE '%supportlogin.io%' ORDER BY step DESC LIMIT 20"
    assert target_action.params["sql"] == "SELECT process_name, command_line FROM process_events WHERE command_line LIKE '%t-161%' ORDER BY step DESC LIMIT 20"
