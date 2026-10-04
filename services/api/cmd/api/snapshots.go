package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Snapshot struct {
	ID              string          `json:"id"`
	EnvironmentID   string          `json:"environment_id"`
	Version         int64           `json:"version"`
	ContentHash     string          `json:"content_hash"`
	Graph           json.RawMessage `json:"graph,omitempty"`
	Vulnerabilities json.RawMessage `json:"vulnerabilities,omitempty"`
	CreatedBy       string          `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
}

func (a *App) snapshot(ctx context.Context, envID, snapshotID string) (Snapshot, error) {
	var item Snapshot
	err := a.Auth.Pool.QueryRow(ctx, "SELECT id,environment_id,version,content_hash,graph,vulnerabilities,created_by,created_at FROM environment_snapshots WHERE environment_id=$1 AND id=$2", envID, snapshotID).Scan(&item.ID, &item.EnvironmentID, &item.Version, &item.ContentHash, &item.Graph, &item.Vulnerabilities, &item.CreatedBy, &item.CreatedAt)
	return item, err
}

func (a *App) registerSnapshotRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/environments/{id}/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		envID := r.PathValue("id")
		session := a.DB.NewSession(r.Context(), neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
		defer session.Close(r.Context())
		capture, err := session.ExecuteWrite(r.Context(), func(tx neo4j.ManagedTransaction) (any, error) {
			if err := lockGraph(r.Context(), tx, envID); err != nil {
				return nil, err
			}
			graph, weaknesses, err := loadGraph(r.Context(), tx.Run, envID)
			if err != nil {
				return nil, err
			}
			return struct {
				Graph      Graph
				Weaknesses []Vulnerability
			}{graph, weaknesses}, nil
		})
		if err != nil {
			fail(w, 500, "graph_error", "Could not capture graph")
			return
		}
		captured := capture.(struct {
			Graph      Graph
			Weaknesses []Vulnerability
		})
		graph, weaknesses := captured.Graph, captured.Weaknesses
		graphJSON, err := json.Marshal(graph)
		if err != nil {
			fail(w, 500, "snapshot_error", "Could not encode graph")
			return
		}
		weaknessJSON, err := json.Marshal(weaknesses)
		if err != nil {
			fail(w, 500, "snapshot_error", "Could not encode vulnerabilities")
			return
		}
		content := append(append([]byte{}, graphJSON...), weaknessJSON...)
		hash := sha256.Sum256(content)
		tx, err := a.Auth.Pool.Begin(r.Context())
		if err != nil {
			fail(w, 500, "database_error", "Could not save snapshot")
			return
		}
		defer tx.Rollback(r.Context())
		var version int64
		if err = tx.QueryRow(r.Context(), "SELECT COALESCE((SELECT max(version) FROM environment_snapshots WHERE environment_id=$1),0)+1 FROM environments WHERE id=$1 FOR UPDATE", envID).Scan(&version); err != nil {
			fail(w, 500, "database_error", "Could not version snapshot")
			return
		}
		item := Snapshot{ID: "snap-" + id(), EnvironmentID: envID, Version: version, ContentHash: hex.EncodeToString(hash[:]), Graph: graphJSON, Vulnerabilities: weaknessJSON, CreatedBy: principal(r).ID}
		if err = tx.QueryRow(r.Context(), "INSERT INTO environment_snapshots(id,environment_id,version,content_hash,graph,vulnerabilities,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at", item.ID, item.EnvironmentID, item.Version, item.ContentHash, item.Graph, item.Vulnerabilities, item.CreatedBy).Scan(&item.CreatedAt); err != nil {
			fail(w, 500, "database_error", "Could not save snapshot")
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			fail(w, 500, "database_error", "Could not save snapshot")
			return
		}
		write(w, 201, item)
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), "SELECT id,environment_id,version,content_hash,created_by,created_at FROM environment_snapshots WHERE environment_id=$1 ORDER BY version DESC", r.PathValue("id"))
		if err != nil {
			fail(w, 500, "database_error", "Could not list snapshots")
			return
		}
		defer rows.Close()
		items := []Snapshot{}
		for rows.Next() {
			var item Snapshot
			if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.Version, &item.ContentHash, &item.CreatedBy, &item.CreatedAt); err != nil {
				fail(w, 500, "database_error", "Could not list snapshots")
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			fail(w, 500, "database_error", "Could not list snapshots")
			return
		}
		write(w, 200, items)
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/snapshots/{snapshotID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		item, err := a.snapshot(r.Context(), r.PathValue("id"), r.PathValue("snapshotID"))
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "not_found", "Snapshot not found")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not load snapshot")
			return
		}
		write(w, 200, item)
	})
}
