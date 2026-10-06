package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type simulationTelemetrySource struct {
	ID               string `json:"id"`
	TimestampSeconds int    `json:"timestamp_seconds"`
	SourceAssetID    string `json:"source_asset_id"`
	TargetAssetID    string `json:"target_asset_id"`
	EventType        string `json:"event_type"`
	Result           string `json:"result"`
	Severity         int    `json:"severity"`
	Detected         bool   `json:"detected"`
}

func telemetryClassification(event simulationTelemetrySource) (string, string) {
	switch event.EventType {
	case "simulation_started":
		return "scenario_started", "scenario"
	case "transition_attempt":
		if event.Result == "prevented" {
			return "control_block", "adversarial"
		}
		return "suspicious_access_attempt", "adversarial"
	case "detection":
		return "endpoint_alert", "control"
	case "target_reached":
		return "sensitive_resource_access", "adversarial"
	default:
		return "simulation_event", "scenario"
	}
}

// A transaction advances telemetry_cursor only after all delivered events and
// matching alerts are written. A restart can therefore retry without duplicates.
func (a *App) ingestDeliveredTelemetry(ctx context.Context) error {
	tx, err := a.Auth.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT j.id,j.environment_id,j.run_id,j.telemetry_cursor,j.event_cursor,r.events
		FROM simulation_jobs j JOIN simulation_runs r ON r.id=j.run_id AND r.environment_id=j.environment_id
		WHERE j.event_cursor>j.telemetry_cursor ORDER BY j.updated_at,j.id LIMIT 20 FOR UPDATE OF j SKIP LOCKED`)
	if err != nil {
		return err
	}
	type pending struct {
		jobID, environmentID, runID string
		from, to                    int
		events                      []byte
	}
	jobs := []pending{}
	for rows.Next() {
		var item pending
		if err = rows.Scan(&item.jobID, &item.environmentID, &item.runID, &item.from, &item.to, &item.events); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, job := range jobs {
		var events []json.RawMessage
		if err = json.Unmarshal(job.events, &events); err != nil {
			return err
		}
		if job.from < 0 || job.to > len(events) {
			return errors.New("invalid telemetry cursor")
		}
		for index := job.from; index < job.to; index++ {
			var source simulationTelemetrySource
			if err = json.Unmarshal(events[index], &source); err != nil {
				return err
			}
			if source.ID == "" || source.TargetAssetID == "" || source.SourceAssetID == "" || source.TimestampSeconds < 0 || source.Severity < 1 || source.Severity > 5 {
				return fmt.Errorf("invalid synthetic event at sequence %d", index+1)
			}
			eventType, groundTruth := telemetryClassification(source)
			telemetryID := "tel-" + job.jobID + "-" + strconv.Itoa(index+1)
			_, err = tx.Exec(ctx, `INSERT INTO security_telemetry(id,environment_id,job_id,run_id,source_event_id,sequence,occurred_at_seconds,event_type,asset_id,source_asset_id,result,severity,detected,ground_truth,payload)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT (job_id,source_event_id) DO NOTHING`, telemetryID, job.environmentID, job.jobID, job.runID, source.ID, index+1, source.TimestampSeconds, eventType, source.TargetAssetID, source.SourceAssetID, source.Result, source.Severity, source.Detected, groundTruth, events[index])
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO security_alerts(id,environment_id,job_id,telemetry_id,rule_id,severity)
				SELECT 'alert-'||r.id||'-'||$1,r.environment_id,$2,$1,r.id,$3 FROM detection_rules r
				WHERE r.environment_id=$4 AND r.enabled AND r.event_type=$5 AND r.min_severity<=$3 AND (r.asset_id='' OR r.asset_id=$6)
				ON CONFLICT (telemetry_id,rule_id) DO NOTHING`, telemetryID, job.jobID, source.Severity, job.environmentID, eventType, source.TargetAssetID)
			if err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, "UPDATE simulation_jobs SET telemetry_cursor=$3 WHERE environment_id=$1 AND id=$2", job.environmentID, job.jobID, job.to); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
