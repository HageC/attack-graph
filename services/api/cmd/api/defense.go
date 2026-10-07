package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type DefenseComparisonConfig struct {
	SimulationConfig
	Iterations                   int     `json:"iterations"`
	ProposedControlEffectiveness float64 `json:"proposed_control_effectiveness"`
	ProposedDetectionCoverage    float64 `json:"proposed_detection_coverage"`
}

func validDefenseComparison(c DefenseComparisonConfig) bool {
	return validSimulationConfig(c.SimulationConfig) && c.Iterations >= 20 && c.Iterations <= 1000 &&
		c.ProposedControlEffectiveness >= 0 && c.ProposedControlEffectiveness <= 1 &&
		c.ProposedDetectionCoverage >= 0 && c.ProposedDetectionCoverage <= 1
}

func (a *App) registerDefenseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/environments/{id}/defense/compare", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input DefenseComparisonConfig
		if !decode(w, r, &input) {
			return
		}
		if !validDefenseComparison(input) {
			fail(w, 422, "invalid_comparison", "Provide a valid snapshot, scenario, 20-1000 iterations, and control and detection values from 0 to 1")
			return
		}
		if len(input.InitialCapabilities) == 0 {
			input.InitialCapabilities = []string{"foothold"}
		}
		snapshot, err := a.snapshot(r.Context(), r.PathValue("id"), input.SnapshotID)
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not_found", "Snapshot not found")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not load snapshot")
			return
		}
		var graph Graph
		var vulnerabilities []Vulnerability
		if json.Unmarshal(snapshot.Graph, &graph) != nil || json.Unmarshal(snapshot.Vulnerabilities, &vulnerabilities) != nil {
			fail(w, 500, "snapshot_error", "Invalid stored snapshot")
			return
		}
		start, target := false, false
		for _, asset := range graph.Assets {
			if asset.ID == input.StartAssetID {
				start = true
			}
			if asset.ID == input.TargetAssetID {
				target = true
			}
		}
		if !start || !target {
			fail(w, 422, "invalid_comparison", "Start and target must exist in the snapshot")
			return
		}
		payload := map[string]any{
			"simulation_id": "compare-" + id(), "assets": graph.Assets,
			"transitions": filterTransitions(graph.Edges), "relationships": filterTopology(graph.Edges),
			"vulnerabilities": vulnerabilities, "start_asset_id": input.StartAssetID,
			"target_asset_id": input.TargetAssetID, "seed": input.Seed,
			"duration_seconds": input.DurationSeconds, "max_steps": input.MaxSteps,
			"initial_capabilities": input.InitialCapabilities, "detection_coverage": input.DetectionCoverage,
			"control_effectiveness": input.ControlEffectiveness, "iterations": input.Iterations,
			"proposed_control_effectiveness": input.ProposedControlEffectiveness,
			"proposed_detection_coverage":    input.ProposedDetectionCoverage,
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, a.SimulationURL+"/compare-defenses", bytes.NewReader(body))
		if err != nil {
			fail(w, 500, "internal", "Could not prepare comparison")
			return
		}
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 60 * time.Second}
		response, err := client.Do(req)
		if err != nil {
			fail(w, 502, "simulation_unavailable", "Comparison service unavailable")
			return
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil || len(data) == 1<<20 || response.StatusCode != 200 || !json.Valid(data) {
			fail(w, 502, "comparison_failed", "Comparison service rejected scenario")
			return
		}
		write(w, 200, json.RawMessage(data))
	})
}
