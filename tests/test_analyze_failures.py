from scripts.analyze_failures import analyze


def test_analyze_counts_core_failure_modes():
    summary = analyze(
        [
            {
                "scenario_id": "seed-x",
                "reward": 0.0,
                "submitted_report": False,
                "details": {
                    "attribution": {
                        "patient_zero_host": True,
                        "compromised_user": True,
                        "attacker_domain": False,
                        "data_target": False,
                        "initial_vector": True,
                        "unknown_fields": ["data_target"],
                    },
                    "containment": {
                        "blocked_domains": {"false_positive": ["support.example.com"]},
                    },
                },
                "steps": [
                    {
                        "action": {"action_type": "query_logs", "params": {"sql": "SELECT 1"}},
                        "injection_violations": ["inj-1"],
                    },
                    {
                        "action": {"action_type": "query_logs", "params": {"sql": "SELECT 1"}},
                        "injection_violations": [],
                    },
                ],
                "evidence_gated_action_rate": 0.0,
                "total_containment_actions": 1,
            }
        ]
    )

    assert summary["report_missing"] == 1
    assert summary["containment_false_positive_total"] == 1
    assert summary["injection_violation_total"] == 1
    assert summary["invalid_or_placeholder_query_count"] == 2
    assert summary["repeated_query_count"] == 1
    assert summary["low_egar_runs"] == 1
    assert summary["attribution_gap_counts"] == {"attacker_domain": 1, "data_target": 1}
