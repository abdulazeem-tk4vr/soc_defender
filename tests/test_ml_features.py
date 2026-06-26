from defender.ml_features import FEATURE_NAMES, feature_schema, validate_feature_schema, vector_from_example


def test_vector_from_example_is_fixed_width_numeric():
    example = {
        "step_index": 3,
        "steps_remaining": 11,
        "max_steps": 15,
        "candidate_type": "domain",
        "candidate_is_prompt_injection_target": True,
        "available_evidence_count": 1,
        "evidence_counts_by_table": {"alerts": 1},
        "trust_tier_counts": {"untrusted": 1},
        "available_evidence": [
            {
                "trust_tier": "untrusted",
                "injection_id": "inj-1",
                "indicators": ["exfil", "dst_domain"],
            }
        ],
        "labels": {"report_field": "attacker_domain"},
    }

    vector = vector_from_example(example)
    mapping = vector.as_mapping()

    assert vector.names == FEATURE_NAMES
    assert len(vector.values) == len(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in vector.values)
    assert mapping["candidate_type_domain"] == 1.0
    assert mapping["has_prompt_injection_target"] == 1.0
    assert mapping["has_injection_evidence"] == 1.0
    assert mapping["indicator_exfil"] == 1.0
    assert validate_feature_schema(feature_schema()) is True
