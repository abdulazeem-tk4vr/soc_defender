from defender import SocDefenderAgent, build_agent
from defender.llm import StaticJSONLLMClient


def test_soc_defender_agent_emits_direct_action_from_observation():
    agent = build_agent(mode="evidence_gate_only", max_steps=15)
    action = agent.act(
        {
            "scenario_id": "s-1",
            "step_index": 0,
            "new_alerts": ["alert-1"],
            "new_emails": [],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert action["action_type"] == "fetch_alert"
    assert action["params"] == {"alert_id": "alert-1"}
    assert agent.max_steps == 10


def test_fixed_steps_are_configurable_and_can_be_disabled():
    configured = SocDefenderAgent(max_steps=17, fixed_steps=7)
    disabled = SocDefenderAgent(max_steps=17, fixed_steps_enabled=False)

    assert configured.max_steps == 7
    assert configured.policy.max_steps == 7
    assert disabled.max_steps == 17
    assert disabled.policy.max_steps == 17


def test_next_action_remains_agent_alias():
    agent = SocDefenderAgent(mode="evidence_gate_only", max_steps=15, fixed_steps_enabled=False)
    action = agent.next_action(
        {
            "scenario_id": "s-1",
            "step_index": 14,
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert action["action_type"] == "submit_report"


def test_report_deadline_uses_episode_max_steps():
    agent = SocDefenderAgent(mode="evidence_gate_only", max_steps=17, fixed_steps_enabled=False)
    step_14_action = agent.next_action(
        {
            "scenario_id": "s-1",
            "step_index": 14,
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )
    step_16_action = agent.next_action(
        {
            "scenario_id": "s-1",
            "step_index": 16,
            "containment": {},
            "last_action_result": {"ok": True, "message": "query_logs", "data": {"rows": []}},
        }
    )

    assert step_14_action["action_type"] != "submit_report"
    assert step_16_action["action_type"] == "submit_report"


def test_complete_report_submits_before_fetching_late_unseen_alert():
    agent = SocDefenderAgent(mode="evidence_gate_only", max_steps=15)
    agent.policy.report_tracker.values.update(
        {
            "patient_zero_host": "h-001",
            "compromised_user": "u-001",
            "attacker_domain": "evil.example",
            "data_target": "t-001",
        }
    )

    action = agent.next_action(
        {
            "scenario_id": "s-1",
            "step_index": 8,
            "new_alerts": ["alert-late"],
            "new_emails": [],
            "containment": {
                "isolated_hosts": ["h-001"],
                "blocked_domains": ["evil.example"],
                "reset_users": ["u-001"],
            },
            "last_action_result": {"ok": True, "message": "query_logs", "data": {"rows": []}},
        }
    )

    assert action["action_type"] == "submit_report"


def test_missing_field_keeps_investigating_when_documented_source_untried():
    agent = SocDefenderAgent(mode="evidence_gate_only", max_steps=15)
    agent.policy.report_tracker.values.update(
        {
            "patient_zero_host": "h-001",
            "compromised_user": "u-001",
            "attacker_domain": "evil.example",
            "data_target": "unknown",
        }
    )

    action = agent.next_action(
        {
            "scenario_id": "s-1",
            "step_index": 8,
            "new_alerts": [],
            "new_emails": [],
            "containment": {
                "isolated_hosts": ["h-001"],
                "blocked_domains": ["evil.example"],
                "reset_users": ["u-001"],
            },
            "last_action_result": {"ok": True, "message": "query_logs", "data": {"rows": []}},
        }
    )

    assert action["action_type"] == "query_logs"
    assert "process_events" in action["params"]["sql"]


def test_missing_field_submits_when_documented_sources_are_exhausted():
    agent = SocDefenderAgent(mode="evidence_gate_only", max_steps=15)
    agent.policy.report_tracker.values.update(
        {
            "patient_zero_host": "h-001",
            "compromised_user": "u-001",
            "attacker_domain": "evil.example",
            "data_target": "unknown",
        }
    )
    agent.policy.sql_planner.record_result(
        "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
        rows_returned=0,
        ok=True,
    )

    action = agent.next_action(
        {
            "scenario_id": "s-1",
            "step_index": 8,
            "new_alerts": [],
            "new_emails": [],
            "containment": {
                "isolated_hosts": ["h-001"],
                "blocked_domains": ["evil.example"],
                "reset_users": ["u-001"],
            },
            "last_action_result": {"ok": True, "message": "query_logs", "data": {"rows": []}},
        }
    )

    assert action["action_type"] == "submit_report"


def test_full_agentic_accepts_mock_llm_client():
    agent = SocDefenderAgent(
        mode="full_agentic",
        max_steps=15,
        llm_client=StaticJSONLLMClient({"intent_type": "query_logs", "action_type": "investigate"}),
    )

    action = agent.act(
        {
            "scenario_id": "s-1",
            "step_index": 0,
            "new_alerts": [],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert action["action_type"] == "query_logs"


def test_full_agentic_disables_prompt_guard2_by_default():
    agent = SocDefenderAgent(mode="full_agentic", max_steps=15)

    assert agent.prompt_guard2_model is None


def test_build_agent_accepts_optional_langgraph_flag():
    agent = build_agent(mode="full_agentic", max_steps=15, use_langgraph=True)

    assert agent.use_langgraph is True


def test_cached_agent_resets_policy_state_between_scenarios():
    agent = build_agent(mode="evidence_gate_only", max_steps=15)
    first = agent.act(
        {
            "scenario_id": "s-1",
            "step_index": 0,
            "new_alerts": ["alert-1"],
            "new_emails": ["email-1"],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert first["action_type"] == "fetch_alert"
    assert agent.policy.fetched_alerts == {"alert-1"}
    agent.policy.registry.add_row(
        {
            "flow_id": "flow-1",
            "dst_domain": "evil.example",
            "trust_tier": "trusted",
            "message": "exfil alert",
        },
        step_seen=1,
    )
    agent.policy.report_tracker.values["attacker_domain"] = "evil.example"
    agent.policy.attempted_containment.add(("block_domain", "evil.example"))
    agent.policy.sql_planner.action_for_sql("SELECT * FROM netflow ORDER BY step DESC LIMIT 20")

    second = agent.act(
        {
            "scenario_id": "s-2",
            "step_index": 0,
            "new_alerts": ["alert-1"],
            "new_emails": [],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert second["action_type"] == "fetch_alert"
    assert second["params"] == {"alert_id": "alert-1"}
    assert agent.policy.current_scenario_id == "s-2"
    assert agent.policy.fetched_alerts == {"alert-1"}
    assert agent.policy.fetched_emails == set()
    assert agent.policy.attempted_containment == set()
    assert agent.policy.registry.supports == []
    assert agent.policy.report_tracker.values["attacker_domain"] == "unknown"
    assert agent.policy.sql_planner.emitted_queries == set()


def test_full_agentic_resets_trace_and_policy_state_between_scenarios():
    agent = SocDefenderAgent(
        mode="full_agentic",
        max_steps=15,
        llm_client=StaticJSONLLMClient({"intent_type": "query_logs", "action_type": "investigate"}),
    )

    agent.act(
        {
            "scenario_id": "s-1",
            "step_index": 0,
            "new_alerts": ["alert-1"],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )
    assert agent.last_graph_state is not None
    agent.policy.registry.add_row(
        {
            "flow_id": "flow-1",
            "dst_domain": "evil.example",
            "trust_tier": "trusted",
            "message": "exfil alert",
        },
        step_seen=1,
    )

    agent.act(
        {
            "scenario_id": "s-2",
            "step_index": 0,
            "new_alerts": [],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert agent.policy.current_scenario_id == "s-2"
    assert agent.policy.registry.supports == []
    assert agent.last_graph_state is not None
    assert agent.last_graph_state.scenario_id == "s-2"
