from app.main import CompareRequest, compare_defenses
from test_simulation import scenario


def test_paired_comparison_reproducible_and_effective():
    base = scenario(detection_coverage=0, control_effectiveness=0).model_dump()
    request = CompareRequest(**base, iterations=100, proposed_control_effectiveness=1,
                             proposed_detection_coverage=1)
    result = compare_defenses(request)
    assert result == compare_defenses(request)
    assert result["baseline"]["target_reached"]["estimate"] == 1
    assert result["proposed"]["target_reached"]["estimate"] == 0
    assert result["target_reached_delta"]["estimate"] == -1
    assert result["proposed"]["detected_run"]["estimate"] == 1


def test_identical_controls_have_zero_paired_delta():
    base = scenario(detection_coverage=0.3, control_effectiveness=0.2).model_dump()
    request = CompareRequest(**base, iterations=30, proposed_control_effectiveness=0.2,
                             proposed_detection_coverage=0.3)
    result = compare_defenses(request)
    assert result["target_reached_delta"]["estimate"] == 0
    assert result["baseline"] == result["proposed"]
