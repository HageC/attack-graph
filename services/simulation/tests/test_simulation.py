from app.main import SimulateRequest, simulate


def scenario(**overrides):
    data = {
        "simulation_id": "sim-test", "seed": 42,
        "assets": [{"id": name, "name": name, "criticality": 3} for name in ("a", "b", "c")],
        "transitions": [
            {"id": "ab", "source": "a", "target": "b", "reason": "modeled", "likelihood": 1, "vulnerability_id": "va", "grants_capability": "operator"},
            {"id": "bc", "source": "b", "target": "c", "reason": "modeled", "likelihood": 1, "vulnerability_id": "vb", "required_capability": "operator"},
        ],
        "relationships": [{"source": "a", "target": "b", "kind": "CAN_REACH"}, {"source": "b", "target": "c", "kind": "CAN_REACH"}],
        "vulnerabilities": [{"id": "va", "asset_id": "a"}, {"id": "vb", "asset_id": "b"}],
        "start_asset_id": "a", "target_asset_id": "c", "detection_coverage": 0,
    }
    data.update(overrides)
    return SimulateRequest(**data)


def test_seeded_run_is_reproducible_and_reaches_target():
    first = simulate(scenario())
    assert first == simulate(scenario())
    assert first["summary"]["result"] == "target_reached"
    assert first["summary"]["successful_transitions"] == 2
    assert [e["timestamp_seconds"] for e in first["events"]] == sorted(e["timestamp_seconds"] for e in first["events"])


def test_control_and_mitigation_prevent_progress():
    blocked = simulate(scenario(control_effectiveness=1))
    assert blocked["summary"]["result"] == "stalled"
    assert blocked["summary"]["successful_transitions"] == 0
    mitigated = simulate(scenario(vulnerabilities=[{"id": "va", "asset_id": "a", "state": "mitigated"}]))
    assert mitigated["summary"]["result"] == "stalled"
    assert len(mitigated["events"]) == 1


def test_full_detection_marks_attempts():
    result = simulate(scenario(detection_coverage=1))
    assert result["summary"]["detected_attempts"] == 2
    assert len([e for e in result["events"] if e["event_type"] == "detection"]) == 2
