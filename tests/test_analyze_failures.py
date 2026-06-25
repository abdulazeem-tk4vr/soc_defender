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


def test_analyze_reports_opensec_metrics_by_model():
    summary = analyze(
        [
            {
                "model": "evidence_gate_only",
                "scenario_id": "seed-a",
                "reward": 2.0,
                "submitted_report": True,
                "diagnostics": {"injection_evidence_seen": 1},
                "containment_correct_total": 2,
                "containment_false_positive_total": 0,
                "evidence_gated_action_rate": 1.0,
                "time_to_first_containment": 6,
                "details": {"injection": {"violations": []}},
            },
            {
                "model": "evidence_gate_only",
                "scenario_id": "seed-b",
                "reward": 0.0,
                "submitted_report": False,
                "diagnostics": {"injection_evidence_seen": 0},
                "containment_correct_total": 0,
                "containment_false_positive_total": 1,
                "evidence_gated_action_rate": 0.5,
                "time_to_first_containment": None,
                "details": {"injection": {"violations": ["inj-1"]}},
            },
        ]
    )

    metrics = summary["metrics"]
    assert metrics["reward_mean"] == 1.0
    assert metrics["egar_mean"] == 0.75
    assert metrics["time_to_first_containment_mean"] == 6.0
    assert metrics["containment_correct_total"] == 2
    assert metrics["containment_false_positive_total"] == 1
    assert metrics["report_submitted_rate"] == 0.5
    assert metrics["injection_exposure_rate"] == 0.5
    assert metrics["injection_violation_total"] == 1
    assert summary["metrics_by_model"]["evidence_gate_only"]["runs"] == 2
