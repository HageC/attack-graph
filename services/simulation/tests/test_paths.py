from app.main import AnalyzeRequest, analyze


def test_capability_is_required_and_accumulates():
    payload = {
        "assets": [{"id": x, "name": x, "criticality": 5} for x in ("a", "b", "c")],
        "transitions": [
            {"id": "ab", "source": "a", "target": "b", "reason": "grant", "likelihood": .8, "grants_capability": "admin", "vulnerability_id": "va"},
            {"id": "bc", "source": "b", "target": "c", "reason": "admin path", "likelihood": .5, "required_capability": "admin", "vulnerability_id": "vb"},
            {"id": "ac", "source": "a", "target": "c", "reason": "blocked", "likelihood": 1, "blocked": True},
        ],
        "relationships": [{"source":"a","target":"b","kind":"CAN_REACH"},{"source":"b","target":"c","kind":"CAN_REACH"}],
        "vulnerabilities": [{"id":"va","asset_id":"a","state":"active"},{"id":"vb","asset_id":"b","state":"active"}],
        "start_asset_id": "a", "target_asset_id": "c",
    }
    paths = analyze(AnalyzeRequest(**payload))
    assert len(paths) == 1
    assert paths[0]["assets"] == ["a", "b", "c"]
    assert paths[0]["likelihood"] == .4


def test_missing_capability_prevents_path():
    request = AnalyzeRequest(assets=[{"id": x, "name": x, "criticality": 1} for x in ("a", "b")], transitions=[{"id": "ab", "source": "a", "target": "b", "reason": "admin", "likelihood": 1, "required_capability": "admin"}], relationships=[{"source":"a","target":"b","kind":"CAN_REACH"}], start_asset_id="a", target_asset_id="b")
    assert analyze(request) == []


def test_transition_needs_matching_topology_relationship():
    request = AnalyzeRequest(assets=[{"id": x, "name": x, "criticality": 1} for x in ("a", "b")], transitions=[{"id": "ab", "source": "a", "target": "b", "reason": "reachable?", "likelihood": 1}], relationships=[], start_asset_id="a", target_asset_id="b")
    assert analyze(request) == []


def test_mitigation_and_source_link_gate_transition():
    payload = {"assets": [{"id": x, "name": x, "criticality": 2} for x in ("a", "b")], "transitions": [{"id": "ab", "source": "a", "target": "b", "reason": "weakness", "likelihood": .8, "vulnerability_id": "v"}], "relationships": [{"source": "a", "target": "b", "kind": "CAN_REACH"}], "start_asset_id": "a", "target_asset_id": "b"}
    assert analyze(AnalyzeRequest(**payload)) == []
    payload["vulnerabilities"] = [{"id": "v", "asset_id": "b", "state": "active"}]
    assert analyze(AnalyzeRequest(**payload)) == []
    payload["vulnerabilities"][0]["asset_id"] = "a"
    assert len(analyze(AnalyzeRequest(**payload))) == 1
    payload["vulnerabilities"][0]["state"] = "mitigated"
    assert analyze(AnalyzeRequest(**payload)) == []
