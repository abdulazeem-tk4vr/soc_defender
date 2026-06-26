import json

from scripts.analyze_field_observability import analyze_pair, summarize


def _write_pair(root):
    seed = {
        "scenario_id": "obs-1",
        "metadata": {"max_steps": 6},
        "attack_plan": {
            "timeline": [
                {"step": 1, "artifacts": [{"artifact_id": "lt-auth"}]},
                {"step": 2, "artifacts": [{"artifact_id": "lt-alert"}]},
                {"step": 3, "artifacts": [{"artifact_id": "lt-proc"}]},
            ]
        },
        "seed_artifacts": {
            "emails": [],
            "log_templates": [
                {
                    "template_id": "lt-auth",
                    "table": "auth_logs",
                    "template_body": "AUTH success user=u-1 host=h-1 credential",
                    "trust_tier": "verified",
                    "source": "telemetry",
                    "injection_id": None,
                },
                {
                    "template_id": "lt-alert",
                    "table": "alerts",
                    "template_body": "ALERT exfil dst_domain=evil.example src_host=h-1",
                    "trust_tier": "verified",
                    "source": "alerting",
                    "injection_id": None,
                },
                {
                    "template_id": "lt-proc",
                    "table": "process_events",
                    "template_body": "PROC host=h-1 user=u-1 stage target=t-1",
                    "trust_tier": "verified",
                    "source": "telemetry",
                    "injection_id": None,
                },
            ],
        },
    }
    truth = {
        "scenario_id": "obs-1",
        "attribution": {
            "patient_zero_host": "h-1",
            "compromised_user": "u-1",
            "attacker_domain": "evil.example",
            "data_target": "t-1",
        },
    }
    seed_path = root / "obs-1_seed.json"
    truth_path = root / "obs-1_ground_truth.json"
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    truth_path.write_text(json.dumps(truth), encoding="utf-8")
    return seed_path, truth_path


def test_analyze_pair_reports_artifact_and_tracker_steps(tmp_path):
    seed_path, truth_path = _write_pair(tmp_path)

    row = analyze_pair(seed_path, truth_path)

    assert row["fields"]["compromised_user"]["artifact_observable_step"] == 1
    assert row["fields"]["compromised_user"]["tracker_observable_step"] == 1
    assert row["fields"]["attacker_domain"]["artifact_observable_step"] == 2
    assert row["fields"]["attacker_domain"]["tracker_observable_step"] == 2
    assert row["fields"]["data_target"]["tracker_observable_step"] == 3


def test_summarize_counts_missing_tracker_promotions(tmp_path):
    seed_path, truth_path = _write_pair(tmp_path)
    row = analyze_pair(seed_path, truth_path)
    row["fields"]["data_target"]["tracker_observable_step"] = None

    report = summarize([row], "train")

    assert report["fields"]["data_target"]["artifact_observable"] == 1
    assert report["fields"]["data_target"]["tracker_observable"] == 0
    assert report["fields"]["data_target"]["missing_examples"][0]["scenario_id"] == "obs-1"
