package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// A job delivers a previously computed synthetic event timeline. The cursor and
// controls live in PostgreSQL so playback survives API restarts.
type SimulationJob struct {
	ID            string            `json:"id"`
	EnvironmentID string            `json:"environment_id"`
	RunID         string            `json:"run_id"`
	Status        string            `json:"status"`
	EventCursor   int               `json:"event_cursor"`
	TotalEvents   int               `json:"total_events"`
	Speed         float64           `json:"speed"`
	Events        []json.RawMessage `json:"events,omitempty"`
	CreatedBy     string            `json:"created_by"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

func validJobSpeed(speed float64) bool { return speed == .5 || speed == 1 || speed == 2 || speed == 4 }

func (a *App) simulationJob(ctx context.Context, envID, jobID string) (SimulationJob, error) {
	var job SimulationJob
	var timeline []byte
	err := a.Auth.Pool.QueryRow(ctx, `SELECT j.id,j.environment_id,j.run_id,j.status,j.event_cursor,jsonb_array_length(r.events),j.speed,r.events,j.created_by,j.created_at,j.updated_at
		FROM simulation_jobs j JOIN simulation_runs r ON r.id=j.run_id AND r.environment_id=j.environment_id WHERE j.environment_id=$1 AND j.id=$2`, envID, jobID).Scan(&job.ID, &job.EnvironmentID, &job.RunID, &job.Status, &job.EventCursor, &job.TotalEvents, &job.Speed, &timeline, &job.CreatedBy, &job.CreatedAt, &job.UpdatedAt)
	if err != nil {
		return job, err
	}
	var all []json.RawMessage
	if err = json.Unmarshal(timeline, &all); err != nil {
		return job, err
	}
	if job.EventCursor > len(all) {
		return job, errors.New("job cursor exceeds event count")
	}
	job.Events = all[:job.EventCursor]
	return job, nil
}

func (a *App) runSimulationJobs(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// One SQL statement advances every active job. The status predicate
			// prevents a concurrent pause or stop from being overwritten.
			_, err := a.Auth.Pool.Exec(ctx, `WITH due AS (
				SELECT j.id, jsonb_array_length(r.events) AS total,
				 (SELECT count(*)::integer FROM jsonb_array_elements(r.events) ev
				  WHERE (ev->>'timestamp_seconds')::double precision <= j.position_seconds + EXTRACT(EPOCH FROM (now()-j.resumed_at))*10*j.speed) AS count
				FROM simulation_jobs j JOIN simulation_runs r ON r.id=j.run_id AND r.environment_id=j.environment_id
				WHERE j.status='running'
			)
			UPDATE simulation_jobs j SET event_cursor=GREATEST(j.event_cursor,due.count),
			 status=CASE WHEN due.count>=due.total THEN 'completed' ELSE 'running' END,
			 updated_at=now()
			FROM due WHERE j.id=due.id AND j.status='running' AND (due.count>j.event_cursor OR due.count>=due.total)`)
			if err != nil {
				slog.Error("simulation job advance failed", "error", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
			if err = a.ingestDeliveredTelemetry(ctx); err != nil {
				slog.Error("simulation telemetry ingestion failed", "error", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}
	}
}

func (a *App) registerSimulationJobRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/environments/{id}/simulations/{runID}/jobs", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var total int
		err := a.Auth.Pool.QueryRow(r.Context(), "SELECT jsonb_array_length(events) FROM simulation_runs WHERE environment_id=$1 AND id=$2", r.PathValue("id"), r.PathValue("runID")).Scan(&total)
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not_found", "Simulation run not found")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not load run")
			return
		}
		jobID := "job-" + id()
		_, err = a.Auth.Pool.Exec(r.Context(), "INSERT INTO simulation_jobs(id,environment_id,run_id,status,created_by) VALUES($1,$2,$3,'running',$4)", jobID, r.PathValue("id"), r.PathValue("runID"), principal(r).ID)
		if databaseConflict(err) {
			fail(w, 409, "job_active", "This run already has an active job")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not start job")
			return
		}
		job, err := a.simulationJob(r.Context(), r.PathValue("id"), jobID)
		if err != nil {
			fail(w, 500, "database_error", "Could not load job")
			return
		}
		write(w, 201, job)
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/simulation-jobs", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), `SELECT j.id,j.environment_id,j.run_id,j.status,j.event_cursor,jsonb_array_length(r.events),j.speed,j.created_by,j.created_at,j.updated_at
			FROM simulation_jobs j JOIN simulation_runs r ON r.id=j.run_id AND r.environment_id=j.environment_id WHERE j.environment_id=$1 ORDER BY j.created_at DESC,j.id DESC LIMIT 50`, r.PathValue("id"))
		if err != nil {
			fail(w, 500, "database_error", "Could not list jobs")
			return
		}
		defer rows.Close()
		jobs := []SimulationJob{}
		for rows.Next() {
			var job SimulationJob
			if err = rows.Scan(&job.ID, &job.EnvironmentID, &job.RunID, &job.Status, &job.EventCursor, &job.TotalEvents, &job.Speed, &job.CreatedBy, &job.CreatedAt, &job.UpdatedAt); err != nil {
				fail(w, 500, "database_error", "Could not list jobs")
				return
			}
			jobs = append(jobs, job)
		}
		if rows.Err() != nil {
			fail(w, 500, "database_error", "Could not list jobs")
			return
		}
		write(w, 200, jobs)
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/simulation-jobs/{jobID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		job, err := a.simulationJob(r.Context(), r.PathValue("id"), r.PathValue("jobID"))
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not_found", "Simulation job not found")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not load job")
			return
		}
		write(w, 200, job)
	})
	mux.HandleFunc("POST /api/v1/environments/{id}/simulation-jobs/{jobID}/{action}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		action := r.PathValue("action")
		var query string
		var args []any
		args = []any{r.PathValue("id"), r.PathValue("jobID")}
		switch action {
		case "pause":
			query = `UPDATE simulation_jobs SET status='paused',position_seconds=position_seconds+EXTRACT(EPOCH FROM (now()-resumed_at))*10*speed,updated_at=now() WHERE environment_id=$1 AND id=$2 AND status='running' RETURNING id`
		case "resume":
			query = `UPDATE simulation_jobs SET status='running',resumed_at=now(),updated_at=now() WHERE environment_id=$1 AND id=$2 AND status='paused' RETURNING id`
		case "stop":
			query = `UPDATE simulation_jobs SET status='stopped',updated_at=now() WHERE environment_id=$1 AND id=$2 AND status IN ('running','paused') RETURNING id`
		case "speed":
			var input struct {
				Speed float64 `json:"speed"`
			}
			if !decode(w, r, &input) {
				return
			}
			if !validJobSpeed(input.Speed) {
				fail(w, 422, "invalid_speed", "Speed must be 0.5, 1, 2, or 4")
				return
			}
			query = `UPDATE simulation_jobs SET position_seconds=CASE WHEN status='running' THEN position_seconds+EXTRACT(EPOCH FROM (now()-resumed_at))*10*speed ELSE position_seconds END,speed=$3,resumed_at=now(),updated_at=now() WHERE environment_id=$1 AND id=$2 AND status IN ('running','paused') RETURNING id`
			args = append(args, input.Speed)
		default:
			fail(w, 404, "not_found", "Job action not found")
			return
		}
		var updated string
		err := a.Auth.Pool.QueryRow(r.Context(), query, args...).Scan(&updated)
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if e := a.Auth.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM simulation_jobs WHERE environment_id=$1 AND id=$2)", args[0], args[1]).Scan(&exists); e != nil {
				fail(w, 500, "database_error", "Could not check job")
				return
			}
			if exists {
				fail(w, 409, "invalid_job_state", "Action is not valid for this job state")
			} else {
				fail(w, 404, "not_found", "Simulation job not found")
			}
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not update job")
			return
		}
		job, err := a.simulationJob(r.Context(), r.PathValue("id"), updated)
		if err != nil {
			fail(w, 500, "database_error", "Could not load job")
			return
		}
		write(w, 200, job)
	})
}
