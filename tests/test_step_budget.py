from defender.budget import budget_state


def test_budget_phases_follow_documented_step_bands():
    assert budget_state(2, 15, 14, 5).phase == "investigate_first"
    assert budget_state(6, 15, 14, 5).phase == "gated_containment"
    assert budget_state(12, 15, 14, 5).phase == "report_fill"


def test_budget_containment_allowed_only_after_min_step_before_report_fill():
    early = budget_state(4, 15, 14, 5)
    middle = budget_state(6, 15, 14, 5)
    late = budget_state(13, 15, 14, 5)

    assert early.containment_allowed is False
    assert middle.containment_allowed is True
    assert late.containment_allowed is False
