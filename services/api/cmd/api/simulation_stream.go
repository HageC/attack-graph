package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jackc/pgx/v5"
)

func (a *App) streamSessionValid(ctx context.Context, r *http.Request) bool {
	p, err := a.Auth.session(ctx, r)
	if err != nil || p.ID != principal(r).ID {
		return false
	}
	var allowed bool
	err = a.Auth.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM environments e JOIN memberships m ON m.organization_id=e.organization_id WHERE e.id=$1 AND m.user_id=$2)`, r.PathValue("id"), p.ID).Scan(&allowed)
	return err == nil && allowed
}

func (a *App) registerSimulationStreamRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/environments/{id}/simulation-jobs/{jobID}/stream", func(w http.ResponseWriter, r *http.Request) {
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
		// Accept enforces same-origin policy. The session and tenant checks above
		// happen before upgrading the connection.
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		closed := conn.CloseRead(ctx)
		send := func(value any) error {
			writeCtx, done := context.WithTimeout(ctx, 5*time.Second)
			defer done()
			return wsjson.Write(writeCtx, conn, value)
		}
		if send(map[string]any{"type": "state", "job": job}) != nil {
			return
		}
		last := job
		if last.Status == "completed" || last.Status == "stopped" {
			return
		}
		updates := time.NewTicker(250 * time.Millisecond)
		defer updates.Stop()
		heartbeat := time.NewTicker(20 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case <-closed.Done():
				return
			case <-heartbeat.C:
				checkCtx, done := context.WithTimeout(ctx, 5*time.Second)
				valid := a.streamSessionValid(checkCtx, r)
				if valid {
					valid = conn.Ping(checkCtx) == nil
				}
				done()
				if !valid {
					return
				}
			case <-updates.C:
				readCtx, done := context.WithTimeout(ctx, 5*time.Second)
				current, e := a.simulationJob(readCtx, r.PathValue("id"), r.PathValue("jobID"))
				done()
				if e != nil {
					return
				}
				for i := last.EventCursor; i < current.EventCursor; i++ {
					if send(map[string]any{"type": "event", "job_id": current.ID, "event_cursor": i + 1, "event": current.Events[i], "updated_at": current.UpdatedAt}) != nil {
						return
					}
				}
				if current.Status != last.Status || current.Speed != last.Speed {
					if send(map[string]any{"type": "state", "job": current}) != nil {
						return
					}
				}
				last = current
				if current.Status == "completed" || current.Status == "stopped" {
					return
				}
			}
		}
	})
}
