from __future__ import annotations

from collections import deque
from random import Random
from math import sqrt
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException

app = FastAPI(title="AttackGraph Simulation API", version="0.1.0")


class Asset(BaseModel):
    id: str
    name: str
    criticality: int = Field(ge=1, le=5)


class Transition(BaseModel):
    id: str
    source: str
    target: str
    reason: str
    likelihood: float = Field(ge=0, le=1)
    required_capability: str = "foothold"
    grants_capability: str = "foothold"
    vulnerability_id: str | None = None
    blocked: bool = False
    required_relationship: str = "CAN_REACH"


class Relationship(BaseModel):
    source: str
    target: str
    kind: str


class Vulnerability(BaseModel):
    id: str
    asset_id: str
    state: str = "active"


class AnalyzeRequest(BaseModel):
    assets: list[Asset]
    transitions: list[Transition]
    relationships: list[Relationship] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    start_asset_id: str
    target_asset_id: str
    max_depth: int = Field(default=6, ge=1, le=12)
    max_paths: int = Field(default=20, ge=1, le=100)
    initial_capabilities: list[str] = Field(default_factory=lambda: ["foothold"])


class SimulateRequest(AnalyzeRequest):
    simulation_id: str = Field(min_length=1, max_length=100)
    seed: int
    duration_seconds: int = Field(default=300, ge=10, le=3600)
    max_steps: int = Field(default=12, ge=1, le=50)
    detection_coverage: float = Field(default=0.25, ge=0, le=1)
    control_effectiveness: float = Field(default=0, ge=0, le=1)


class CompareRequest(SimulateRequest):
    iterations: int = Field(default=200, ge=20, le=1000)
    proposed_control_effectiveness: float = Field(ge=0, le=1)
    proposed_detection_coverage: float = Field(ge=0, le=1)


def compare_defenses(request: CompareRequest) -> dict:
    """Paired scenarios use the same seed per iteration to reduce sampling noise."""
    baseline, proposed = [], []
    for index in range(request.iterations):
        seed = request.seed + index
        common = request.model_dump(exclude={"iterations", "proposed_control_effectiveness", "proposed_detection_coverage"})
        common.update(seed=seed, simulation_id=f"{request.simulation_id}-{index}")
        first_run = simulate(SimulateRequest(**common))
        common.update(control_effectiveness=request.proposed_control_effectiveness,
                      detection_coverage=request.proposed_detection_coverage)
        second_run = simulate(SimulateRequest(**common))
        baseline.append(first_run)
        proposed.append(second_run)

    def rate_interval(hits: int) -> dict:
        n = request.iterations
        z = 1.96
        center = (hits / n + z * z / (2 * n)) / (1 + z * z / n)
        radius = z * sqrt((hits / n) * (1 - hits / n) / n + z * z / (4 * n * n)) / (1 + z * z / n)
        return {"estimate": round(hits / n, 4), "ci95": [round(max(0, center - radius), 4), round(min(1, center + radius), 4)]}

    def percentile(values: list[int], fraction: float) -> int | None:
        if not values:
            return None
        ordered = sorted(values)
        return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction + 0.5))]

    def summarize(items: list[dict]) -> dict:
        summaries = [item["summary"] for item in items]
        reached = sum(item["result"] == "target_reached" for item in summaries)
        detected = sum(item["detected_attempts"] > 0 for item in summaries)
        detection_times = [next(event["timestamp_seconds"] for event in item["events"] if event["event_type"] == "detection")
                           for item in items if any(event["event_type"] == "detection" for event in item["events"])]
        target_times = [item["summary"]["elapsed_seconds"] for item in items if item["summary"]["result"] == "target_reached"]
        affected = [len({request.start_asset_id} | {event["target_asset_id"] for event in item["events"]
                      if event["event_type"] == "transition_attempt" and event["result"] == "succeeded"}) for item in items]
        return {"target_reached": rate_interval(reached), "detected_run": rate_interval(detected),
                "mean_successful_transitions": round(sum(item["successful_transitions"] for item in summaries) / len(items), 3),
                "mean_assets_affected": round(sum(affected) / len(items), 3),
                "mean_elapsed_seconds": round(sum(item["elapsed_seconds"] for item in summaries) / len(items), 2),
                "median_time_to_detection_seconds": percentile(detection_times, 0.5),
                "median_time_to_target_seconds": percentile(target_times, 0.5),
                "p95_time_to_target_seconds": percentile(target_times, 0.95)}

    differences = [int(after["summary"]["result"] == "target_reached") - int(before["summary"]["result"] == "target_reached")
                   for before, after in zip(baseline, proposed)]
    mean = sum(differences) / len(differences)
    variance = sum((value - mean) ** 2 for value in differences) / (len(differences) - 1)
    margin = 1.96 * sqrt(variance / len(differences))
    return {"iterations": request.iterations, "seed": request.seed, "baseline": summarize(baseline),
            "proposed": summarize(proposed), "target_reached_delta": {
                "estimate": round(mean, 4), "ci95": [round(max(-1, mean - margin), 4), round(min(1, mean + margin), 4)]},
            "assumptions": "Independent seeded runs; paired baseline/proposed seeds. Wilson intervals for rates and a normal paired-difference interval. Configured transition probabilities are synthetic model estimates, not empirical breach probabilities."}


def analyze(request: AnalyzeRequest) -> list[dict]:
    assets = {asset.id: asset for asset in request.assets}
    if request.start_asset_id not in assets or request.target_asset_id not in assets:
        raise ValueError("Start and target must exist in the environment")
    outgoing: dict[str, list[Transition]] = {}
    relationships = {(item.source, item.target, item.kind) for item in request.relationships}
    active_weaknesses = {(item.id, item.asset_id) for item in request.vulnerabilities if item.state == "active"}
    for transition in request.transitions:
        if transition.source in assets and transition.target in assets and not transition.blocked and (transition.source, transition.target, transition.required_relationship) in relationships and (transition.vulnerability_id, transition.source) in active_weaknesses:
            outgoing.setdefault(transition.source, []).append(transition)
    for edges in outgoing.values():
        edges.sort(key=lambda item: item.id)

    queue = deque([(request.start_asset_id, [request.start_asset_id], [], frozenset(request.initial_capabilities), 1.0)])
    paths = []
    while queue and len(paths) < request.max_paths:
        current, nodes, steps, capabilities, likelihood = queue.popleft()
        if current == request.target_asset_id and steps:
            impact = assets[current].criticality * 20
            paths.append({
                "assets": nodes,
                "steps": steps,
                "likelihood": round(likelihood, 4),
                "impact": impact,
                "risk_score": round(likelihood * impact, 1),
            })
            continue
        if len(steps) >= request.max_depth:
            continue
        for edge in outgoing.get(current, []):
            if edge.target in nodes or edge.required_capability not in capabilities:
                continue
            granted = capabilities | {edge.grants_capability}
            step = {
                "transition_id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "reason": edge.reason,
                "required_capability": edge.required_capability,
                "grants_capability": edge.grants_capability,
                "vulnerability_id": edge.vulnerability_id,
            }
            queue.append((edge.target, nodes + [edge.target], steps + [step], granted, likelihood * edge.likelihood))
    return sorted(paths, key=lambda path: (-path["risk_score"], len(path["steps"])))


def simulate(request: SimulateRequest) -> dict:
    assets = {asset.id: asset for asset in request.assets}
    if request.start_asset_id not in assets or request.target_asset_id not in assets:
        raise ValueError("Start and target must exist in the snapshot")
    if request.start_asset_id == request.target_asset_id:
        raise ValueError("Start and target must differ")
    relationships = {(item.source, item.target, item.kind) for item in request.relationships}
    weaknesses = {(item.id, item.asset_id) for item in request.vulnerabilities if item.state == "active"}
    outgoing: dict[str, list[Transition]] = {}
    for edge in request.transitions:
        if (edge.source in assets and edge.target in assets and not edge.blocked
                and (edge.source, edge.target, edge.required_relationship) in relationships
                and (edge.vulnerability_id, edge.source) in weaknesses):
            outgoing.setdefault(edge.source, []).append(edge)
    for candidates in outgoing.values():
        candidates.sort(key=lambda item: item.id)

    rng = Random(request.seed)
    current = request.start_asset_id
    visited = {current}
    capabilities = set(request.initial_capabilities)
    events = []
    elapsed = 0
    successes = 0
    detected_count = 0
    result = "stalled"

    def add_event(kind: str, source: str, target: str, edge: Transition | None,
                  outcome: str, detected: bool, seconds: int) -> None:
        events.append({
            "id": f"{request.simulation_id}-event-{len(events) + 1:03d}",
            "simulation_id": request.simulation_id,
            "timestamp_seconds": seconds,
            "source_asset_id": source,
            "target_asset_id": target,
            "event_type": kind,
            "transition_id": edge.id if edge else None,
            "technique_id": None,
            "preconditions": {"capability": edge.required_capability,
                              "relationship": edge.required_relationship,
                              "vulnerability_id": edge.vulnerability_id} if edge else {},
            "result": outcome,
            "detected": detected,
            "severity": assets[target].criticality if target in assets else assets[source].criticality,
            "metadata": {"synthetic": True},
        })

    add_event("simulation_started", current, current, None, "started", False, elapsed)
    for _ in range(request.max_steps):
        candidates = [edge for edge in outgoing.get(current, [])
                      if edge.target not in visited and edge.required_capability in capabilities]
        if not candidates:
            break
        edge = candidates[rng.randrange(len(candidates))]
        delay = rng.randint(5, 30)
        if elapsed + delay > request.duration_seconds:
            result = "duration_exceeded"
            break
        elapsed += delay
        detected = rng.random() < request.detection_coverage
        detected_count += int(detected)
        success = rng.random() < edge.likelihood * (1 - request.control_effectiveness)
        add_event("transition_attempt", current, edge.target, edge,
                  "succeeded" if success else "prevented", detected, elapsed)
        if detected:
            add_event("detection", current, edge.target, edge, "observed", True, elapsed)
        if not success:
            visited.add(edge.target)
            continue
        successes += 1
        current = edge.target
        visited.add(current)
        capabilities.add(edge.grants_capability)
        if current == request.target_asset_id:
            result = "target_reached"
            add_event("target_reached", current, current, None, "reached", detected, elapsed)
            break
    else:
        if result == "stalled":
            result = "step_limit"
    return {"summary": {"result": result, "end_asset_id": current,
                        "event_count": len(events), "successful_transitions": successes,
                        "detected_attempts": detected_count, "elapsed_seconds": elapsed},
            "events": events}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze_route(request: AnalyzeRequest):
    try:
        return {"paths": analyze(request), "score_note": "Model estimate from configured transition likelihoods; not a real-world exploitation probability."}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/simulate")
def simulate_route(request: SimulateRequest):
    try:
        return simulate(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/compare-defenses")
def compare_defenses_route(request: CompareRequest):
    try:
        return compare_defenses(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
