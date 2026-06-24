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


def test_next_action_remains_agent_alias():
    agent = SocDefenderAgent(mode="evidence_gate_only", max_steps=15)
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
    agent = SocDefenderAgent(mode="evidence_gate_only", max_steps=17)
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
