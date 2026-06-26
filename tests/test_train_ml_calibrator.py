import json

from defender.ml_features import feature_schema_hash
from scripts.train_ml_calibrator import write_artifacts


def test_write_artifacts_creates_train_manifest_and_schemas(tmp_path):
    examples = [
        {
            "scenario_id": "seed-1",
            "step_index": 0,
            "steps_remaining": 2,
            "max_steps": 3,
            "candidate_type": "host",
            "candidate_value": "h-1",
            "available_evidence_count": 1,
            "available_evidence": [],
            "evidence_counts_by_table": {"auth_logs": 1},
            "trust_tier_counts": {"verified": 1},
            "labels": {
                "investigation_objective": "find_patient_zero",
                "containment_sufficiency": "sufficient_evidence",
            },
        }
    ]
    artifact_dir = tmp_path / "artifact"

    manifest = write_artifacts(
        examples,
        artifact_dir,
        source_examples=tmp_path / "train_examples.jsonl",
        train_dir=tmp_path / "train",
        train_xgboost=False,
        train_unsupervised=False,
    )

    schema = json.loads((artifact_dir / "feature_schema.json").read_text(encoding="utf-8"))
    label_schema = json.loads((artifact_dir / "label_schema.json").read_text(encoding="utf-8"))
    saved_manifest = json.loads((artifact_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["source_split"] == "train"
    assert saved_manifest["feature_schema_hash"] == feature_schema_hash(schema)
    assert label_schema["objective_counts"] == {"find_patient_zero": 1}
    assert label_schema["containment_priors"]["sufficient_evidence"] == 1.0
