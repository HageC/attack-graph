package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type InvestigationReport struct {
	SchemaVersion   int             `json:"schema_version"`
	EnvironmentID   string          `json:"environment_id"`
	RunID           string          `json:"run_id"`
	SnapshotID      string          `json:"snapshot_id"`
	SnapshotHash    string          `json:"snapshot_hash"`
	Seed            int64           `json:"seed"`
	Config          json.RawMessage `json:"config"`
	Summary         json.RawMessage `json:"summary"`
	Events          json.RawMessage `json:"events"`
	RunCreatedAt    time.Time       `json:"run_created_at"`
	DeliveredEvents int64           `json:"delivered_events"`
	AlertCount      int64           `json:"alert_count"`
	Alerts          []SecurityAlert `json:"alerts"`
	EvidenceLimit   int             `json:"evidence_limit"`
	Caveat          string          `json:"caveat"`
}

func (a *App) registerReportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/environments/{id}/reports/{runID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		envID, runID := r.PathValue("id"), r.PathValue("runID")
		report := InvestigationReport{SchemaVersion: 1, EnvironmentID: envID, RunID: runID, Alerts: []SecurityAlert{}, EvidenceLimit: 200,
			Caveat: "All assets, actions, events, and detections are synthetic. Configured likelihoods and outcomes are model estimates, not evidence of a real incident."}
		err := a.Auth.Pool.QueryRow(r.Context(), `SELECT r.snapshot_id,s.content_hash,r.seed,r.config,r.summary,r.events,r.created_at FROM simulation_runs r JOIN environment_snapshots s ON s.id=r.snapshot_id AND s.environment_id=r.environment_id WHERE r.environment_id=$1 AND r.id=$2`, envID, runID).Scan(&report.SnapshotID, &report.SnapshotHash, &report.Seed, &report.Config, &report.Summary, &report.Events, &report.RunCreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not_found", "Report run not found")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not load report")
			return
		}
		err = a.Auth.Pool.QueryRow(r.Context(), `SELECT count(*) FROM security_telemetry WHERE environment_id=$1 AND run_id=$2`, envID, runID).Scan(&report.DeliveredEvents)
		if err != nil {
			fail(w, 500, "database_error", "Could not count report telemetry")
			return
		}
		err = a.Auth.Pool.QueryRow(r.Context(), `SELECT count(*) FROM security_alerts a JOIN security_telemetry t ON t.id=a.telemetry_id WHERE a.environment_id=$1 AND t.run_id=$2`, envID, runID).Scan(&report.AlertCount)
		if err != nil {
			fail(w, 500, "database_error", "Could not count report alerts")
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), `SELECT a.id,a.environment_id,a.job_id,a.telemetry_id,a.rule_id,d.name,t.event_type,t.asset_id,a.severity,a.created_at FROM security_alerts a JOIN security_telemetry t ON t.id=a.telemetry_id JOIN detection_rules d ON d.id=a.rule_id WHERE a.environment_id=$1 AND t.run_id=$2 ORDER BY a.created_at,a.id LIMIT 200`, envID, runID)
		if err != nil {
			fail(w, 500, "database_error", "Could not load report alerts")
			return
		}
		for rows.Next() {
			var item SecurityAlert
			if rows.Scan(&item.ID, &item.EnvironmentID, &item.JobID, &item.TelemetryID, &item.RuleID, &item.RuleName, &item.EventType, &item.AssetID, &item.Severity, &item.CreatedAt) != nil {
				rows.Close()
				fail(w, 500, "database_error", "Could not load report alerts")
				return
			}
			report.Alerts = append(report.Alerts, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			fail(w, 500, "database_error", "Could not load report alerts")
			return
		}
		write(w, 200, report)
	})
}
