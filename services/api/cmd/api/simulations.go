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

type SimulationConfig struct {
	SnapshotID           string   `json:"snapshot_id"`
	StartAssetID         string   `json:"start_asset_id"`
	TargetAssetID        string   `json:"target_asset_id"`
	Seed                 *int64   `json:"seed"`
	DurationSeconds      int      `json:"duration_seconds"`
	MaxSteps             int      `json:"max_steps"`
	InitialCapabilities  []string `json:"initial_capabilities"`
	DetectionCoverage    float64  `json:"detection_coverage"`
	ControlEffectiveness float64  `json:"control_effectiveness"`
}

type SimulationRun struct {
	ID            string          `json:"id"`
	EnvironmentID string          `json:"environment_id"`
	SnapshotID    string          `json:"snapshot_id"`
	Seed          int64           `json:"seed"`
	Config        json.RawMessage `json:"config"`
	Summary       json.RawMessage `json:"summary"`
	Events        json.RawMessage `json:"events,omitempty"`
	CreatedBy     string          `json:"created_by"`
	CreatedAt     time.Time       `json:"created_at"`
}

func validSimulationConfig(c SimulationConfig) bool {
	if c.SnapshotID == "" || c.StartAssetID == "" || c.TargetAssetID == "" || c.StartAssetID == c.TargetAssetID || c.Seed == nil || c.DurationSeconds < 10 || c.DurationSeconds > 3600 || c.MaxSteps < 1 || c.MaxSteps > 50 || c.DetectionCoverage < 0 || c.DetectionCoverage > 1 || c.ControlEffectiveness < 0 || c.ControlEffectiveness > 1 || len(c.InitialCapabilities) > 4 {
		return false
	}
	allowed := map[string]bool{"foothold": true, "identity": true, "operator": true, "service_identity": true}
	for _, capability := range c.InitialCapabilities {
		if !allowed[capability] {
			return false
		}
	}
	return true
}

func (a *App) registerSimulationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/environments/{id}/simulations", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var config SimulationConfig
		if !decode(w, r, &config) {
			return
		}
		if !validSimulationConfig(config) {
			fail(w, 422, "invalid_simulation", "Provide a snapshot, distinct assets, seed, duration 10-3600, max steps 1-50, and coverage values 0-1")
			return
		}
		if len(config.InitialCapabilities) == 0 {
			config.InitialCapabilities = []string{"foothold"}
		}
		envID := r.PathValue("id")
		snapshot, err := a.snapshot(r.Context(), envID, config.SnapshotID)
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
			if asset.ID == config.StartAssetID {
				start = true
			}
			if asset.ID == config.TargetAssetID {
				target = true
			}
		}
		if !start || !target {
			fail(w, 422, "invalid_simulation", "Start and target must exist in the snapshot")
			return
		}
		run := SimulationRun{ID: "sim-" + id(), EnvironmentID: envID, SnapshotID: config.SnapshotID, Seed: *config.Seed, CreatedBy: principal(r).ID}
		payload := map[string]any{"simulation_id": run.ID, "assets": graph.Assets, "transitions": filterTransitions(graph.Edges), "relationships": filterTopology(graph.Edges), "vulnerabilities": vulnerabilities, "start_asset_id": config.StartAssetID, "target_asset_id": config.TargetAssetID, "seed": config.Seed, "duration_seconds": config.DurationSeconds, "max_steps": config.MaxSteps, "initial_capabilities": config.InitialCapabilities, "detection_coverage": config.DetectionCoverage, "control_effectiveness": config.ControlEffectiveness}
		body, _ := json.Marshal(payload)
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, a.SimulationURL+"/simulate", bytes.NewReader(body))
		if err != nil {
			fail(w, 500, "internal", "Could not prepare simulation")
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := a.Client.Do(request)
		if err != nil {
			fail(w, 502, "simulation_unavailable", "Simulation service unavailable")
			return
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil || len(data) == 2<<20 {
			fail(w, 502, "simulation_failed", "Invalid simulation response")
			return
		}
		if response.StatusCode != 200 {
			fail(w, 502, "simulation_failed", "Simulation service rejected run")
			return
		}
		var result struct {
			Summary json.RawMessage `json:"summary"`
			Events  json.RawMessage `json:"events"`
		}
		if json.Unmarshal(data, &result) != nil || len(result.Summary) == 0 || len(result.Events) == 0 || result.Summary[0] != '{' || result.Events[0] != '[' {
			fail(w, 502, "simulation_failed", "Invalid simulation response")
			return
		}
		run.Config, _ = json.Marshal(config)
		run.Summary, run.Events = result.Summary, result.Events
		err = a.Auth.Pool.QueryRow(r.Context(), "INSERT INTO simulation_runs(id,environment_id,snapshot_id,seed,config,summary,events,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at", run.ID, envID, run.SnapshotID, run.Seed, run.Config, run.Summary, run.Events, run.CreatedBy).Scan(&run.CreatedAt)
		if err != nil {
			fail(w, 500, "database_error", "Could not save simulation")
			return
		}
		write(w, 201, run)
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/simulations", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), "SELECT id,environment_id,snapshot_id,seed,config,summary,created_by,created_at FROM simulation_runs WHERE environment_id=$1 ORDER BY created_at DESC,id DESC LIMIT 50", r.PathValue("id"))
		if err != nil {
			fail(w, 500, "database_error", "Could not list simulations")
			return
		}
		defer rows.Close()
		runs := []SimulationRun{}
		for rows.Next() {
			var run SimulationRun
			if err = rows.Scan(&run.ID, &run.EnvironmentID, &run.SnapshotID, &run.Seed, &run.Config, &run.Summary, &run.CreatedBy, &run.CreatedAt); err != nil {
				fail(w, 500, "database_error", "Could not list simulations")
				return
			}
			runs = append(runs, run)
		}
		if rows.Err() != nil {
			fail(w, 500, "database_error", "Could not list simulations")
			return
		}
		write(w, 200, runs)
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/simulations/{runID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var run SimulationRun
		err := a.Auth.Pool.QueryRow(r.Context(), "SELECT id,environment_id,snapshot_id,seed,config,summary,events,created_by,created_at FROM simulation_runs WHERE environment_id=$1 AND id=$2", r.PathValue("id"), r.PathValue("runID")).Scan(&run.ID, &run.EnvironmentID, &run.SnapshotID, &run.Seed, &run.Config, &run.Summary, &run.Events, &run.CreatedBy, &run.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not_found", "Simulation not found")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not load simulation")
			return
		}
		write(w, 200, run)
	})
}
