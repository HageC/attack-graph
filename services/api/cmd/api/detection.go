package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var allowedTelemetryTypes = map[string]bool{
	"scenario_started": true, "suspicious_access_attempt": true, "control_block": true,
	"endpoint_alert": true, "sensitive_resource_access": true, "simulation_event": true,
}
var ruleAssetID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,100}$`)

type DetectionRule struct {
	ID            string    `json:"id"`
	EnvironmentID string    `json:"environment_id"`
	Name          string    `json:"name"`
	Enabled       bool      `json:"enabled"`
	EventType     string    `json:"event_type"`
	MinSeverity   int       `json:"min_severity"`
	AssetID       string    `json:"asset_id"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type SecurityTelemetry struct {
	ID                string          `json:"id"`
	EnvironmentID     string          `json:"environment_id"`
	JobID             string          `json:"job_id"`
	RunID             string          `json:"run_id"`
	SourceEventID     string          `json:"source_event_id"`
	Sequence          int             `json:"sequence"`
	SchemaVersion     int             `json:"schema_version"`
	OccurredAtSeconds int             `json:"occurred_at_seconds"`
	EventType         string          `json:"event_type"`
	AssetID           string          `json:"asset_id"`
	SourceAssetID     string          `json:"source_asset_id"`
	Result            string          `json:"result"`
	Severity          int             `json:"severity"`
	Detected          bool            `json:"detected"`
	GroundTruth       string          `json:"ground_truth"`
	Payload           json.RawMessage `json:"payload"`
	CreatedAt         time.Time       `json:"created_at"`
}

type SecurityAlert struct {
	ID            string    `json:"id"`
	EnvironmentID string    `json:"environment_id"`
	JobID         string    `json:"job_id"`
	TelemetryID   string    `json:"telemetry_id"`
	RuleID        string    `json:"rule_id"`
	RuleName      string    `json:"rule_name"`
	EventType     string    `json:"event_type"`
	AssetID       string    `json:"asset_id"`
	Severity      int       `json:"severity"`
	CreatedAt     time.Time `json:"created_at"`
}

func validDetectionRule(rule DetectionRule) bool {
	name := strings.TrimSpace(rule.Name)
	return len(name) >= 3 && len(name) <= 80 && allowedTelemetryTypes[rule.EventType] && rule.MinSeverity >= 1 && rule.MinSeverity <= 5 && (rule.AssetID == "" || ruleAssetID.MatchString(rule.AssetID))
}

func (a *App) registerDetectionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/environments/{id}/telemetry", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		query := r.URL.Query()
		minimum := 0
		if query.Has("min_severity") {
			var err error
			minimum, err = strconv.Atoi(query.Get("min_severity"))
			if err != nil || minimum < 1 || minimum > 5 {
				fail(w, 422, "invalid_filter", "min_severity must be 1 to 5")
				return
			}
		}
		limit := 100
		if query.Has("limit") {
			var err error
			limit, err = strconv.Atoi(query.Get("limit"))
			if err != nil || limit < 1 || limit > 200 {
				fail(w, 422, "invalid_filter", "limit must be 1 to 200")
				return
			}
		}
		if eventType := query.Get("event_type"); eventType != "" && !allowedTelemetryTypes[eventType] {
			fail(w, 422, "invalid_filter", "Unsupported event type")
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), `SELECT id,environment_id,job_id,run_id,source_event_id,sequence,schema_version,occurred_at_seconds,event_type,asset_id,source_asset_id,result,severity,detected,ground_truth,payload,created_at
			FROM security_telemetry WHERE environment_id=$1 AND ($2='' OR job_id=$2) AND ($3='' OR run_id=$3) AND ($4='' OR event_type=$4) AND ($5='' OR asset_id=$5) AND severity >= $6
			ORDER BY created_at DESC,id DESC LIMIT $7`, r.PathValue("id"), query.Get("job_id"), query.Get("run_id"), query.Get("event_type"), query.Get("asset_id"), minimum, limit)
		if err != nil {
			fail(w, 500, "database_error", "Could not list telemetry")
			return
		}
		defer rows.Close()
		items := []SecurityTelemetry{}
		for rows.Next() {
			var item SecurityTelemetry
			if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.JobID, &item.RunID, &item.SourceEventID, &item.Sequence, &item.SchemaVersion, &item.OccurredAtSeconds, &item.EventType, &item.AssetID, &item.SourceAssetID, &item.Result, &item.Severity, &item.Detected, &item.GroundTruth, &item.Payload, &item.CreatedAt); err != nil {
				fail(w, 500, "database_error", "Could not list telemetry")
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			fail(w, 500, "database_error", "Could not list telemetry")
			return
		}
		write(w, 200, items)
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/alerts", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		limit := 100
		if r.URL.Query().Has("limit") {
			var err error
			limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
			if err != nil || limit < 1 || limit > 200 {
				fail(w, 422, "invalid_filter", "limit must be 1 to 200")
				return
			}
		}
		rows, err := a.Auth.Pool.Query(r.Context(), `SELECT a.id,a.environment_id,a.job_id,a.telemetry_id,a.rule_id,r.name,t.event_type,t.asset_id,a.severity,a.created_at
			FROM security_alerts a JOIN detection_rules r ON r.id=a.rule_id JOIN security_telemetry t ON t.id=a.telemetry_id
			WHERE a.environment_id=$1 AND ($2='' OR a.job_id=$2) ORDER BY a.created_at DESC,a.id DESC LIMIT $3`, r.PathValue("id"), r.URL.Query().Get("job_id"), limit)
		if err != nil {
			fail(w, 500, "database_error", "Could not list alerts")
			return
		}
		defer rows.Close()
		items := []SecurityAlert{}
		for rows.Next() {
			var item SecurityAlert
			if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.JobID, &item.TelemetryID, &item.RuleID, &item.RuleName, &item.EventType, &item.AssetID, &item.Severity, &item.CreatedAt); err != nil {
				fail(w, 500, "database_error", "Could not list alerts")
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			fail(w, 500, "database_error", "Could not list alerts")
			return
		}
		write(w, 200, items)
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/detection-rules", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), "SELECT id,environment_id,name,enabled,event_type,min_severity,asset_id,created_by,created_at,updated_at FROM detection_rules WHERE environment_id=$1 ORDER BY created_at DESC,id DESC", r.PathValue("id"))
		if err != nil {
			fail(w, 500, "database_error", "Could not list detection rules")
			return
		}
		defer rows.Close()
		items := []DetectionRule{}
		for rows.Next() {
			var item DetectionRule
			if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Enabled, &item.EventType, &item.MinSeverity, &item.AssetID, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
				fail(w, 500, "database_error", "Could not list detection rules")
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			fail(w, 500, "database_error", "Could not list detection rules")
			return
		}
		write(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/environments/{id}/detection-rules", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input struct {
			Name        string `json:"name"`
			EventType   string `json:"event_type"`
			MinSeverity int    `json:"min_severity"`
			AssetID     string `json:"asset_id"`
		}
		if !decode(w, r, &input) {
			return
		}
		rule := DetectionRule{ID: "rule-" + id(), EnvironmentID: r.PathValue("id"), Name: strings.TrimSpace(input.Name), Enabled: true, EventType: input.EventType, MinSeverity: input.MinSeverity, AssetID: input.AssetID, CreatedBy: principal(r).ID}
		if !validDetectionRule(rule) {
			fail(w, 422, "invalid_rule", "Provide a name, supported event type, severity 1-5, and optional asset ID")
			return
		}
		err := a.Auth.Pool.QueryRow(r.Context(), "INSERT INTO detection_rules(id,environment_id,name,event_type,min_severity,asset_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at,updated_at", rule.ID, rule.EnvironmentID, rule.Name, rule.EventType, rule.MinSeverity, rule.AssetID, rule.CreatedBy).Scan(&rule.CreatedAt, &rule.UpdatedAt)
		if databaseConflict(err) {
			fail(w, 409, "rule_exists", "A rule with that name already exists")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not create rule")
			return
		}
		write(w, 201, rule)
	})
	mux.HandleFunc("PATCH /api/v1/environments/{id}/detection-rules/{ruleID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input struct {
			Enabled *bool `json:"enabled"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Enabled == nil {
			fail(w, 422, "invalid_rule", "enabled is required")
			return
		}
		var rule DetectionRule
		err := a.Auth.Pool.QueryRow(r.Context(), `UPDATE detection_rules SET enabled=$3,updated_at=now() WHERE environment_id=$1 AND id=$2
			RETURNING id,environment_id,name,enabled,event_type,min_severity,asset_id,created_by,created_at,updated_at`, r.PathValue("id"), r.PathValue("ruleID"), *input.Enabled).Scan(&rule.ID, &rule.EnvironmentID, &rule.Name, &rule.Enabled, &rule.EventType, &rule.MinSeverity, &rule.AssetID, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not_found", "Detection rule not found")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not update rule")
			return
		}
		write(w, 200, rule)
	})
	mux.HandleFunc("POST /api/v1/environments/{id}/detection-rules/{ruleID}/test", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input struct {
			JobID string `json:"job_id"`
		}
		if !decode(w, r, &input) {
			return
		}
		var rule DetectionRule
		err := a.Auth.Pool.QueryRow(r.Context(), "SELECT id,environment_id,name,enabled,event_type,min_severity,asset_id,created_by,created_at,updated_at FROM detection_rules WHERE environment_id=$1 AND id=$2", r.PathValue("id"), r.PathValue("ruleID")).Scan(&rule.ID, &rule.EnvironmentID, &rule.Name, &rule.Enabled, &rule.EventType, &rule.MinSeverity, &rule.AssetID, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not_found", "Detection rule not found")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not load rule")
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), `SELECT id FROM security_telemetry WHERE environment_id=$1 AND event_type=$2 AND severity >= $3 AND ($4='' OR asset_id=$4) AND ($5='' OR job_id=$5) ORDER BY created_at DESC,id DESC LIMIT 100`, rule.EnvironmentID, rule.EventType, rule.MinSeverity, rule.AssetID, input.JobID)
		if err != nil {
			fail(w, 500, "database_error", "Could not test rule")
			return
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				fail(w, 500, "database_error", "Could not test rule")
				return
			}
			ids = append(ids, id)
		}
		if rows.Err() != nil {
			rows.Close()
			fail(w, 500, "database_error", "Could not test rule")
			return
		}
		rows.Close()
		var count int
		err = a.Auth.Pool.QueryRow(r.Context(), `SELECT count(*) FROM security_telemetry WHERE environment_id=$1 AND event_type=$2 AND severity >= $3 AND ($4='' OR asset_id=$4) AND ($5='' OR job_id=$5)`, rule.EnvironmentID, rule.EventType, rule.MinSeverity, rule.AssetID, input.JobID).Scan(&count)
		if err != nil {
			fail(w, 500, "database_error", "Could not test rule")
			return
		}
		write(w, 200, map[string]any{"rule_id": rule.ID, "match_count": count, "telemetry_ids": ids, "truncated": count > len(ids), "enabled": rule.Enabled})
	})
}
