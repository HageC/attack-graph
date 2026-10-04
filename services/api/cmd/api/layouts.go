package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type LayoutPosition struct {
	X int `json:"x"`
	Y int `json:"y"`
}
type GraphLayout struct {
	ID            string                    `json:"id"`
	EnvironmentID string                    `json:"environment_id"`
	Name          string                    `json:"name"`
	Positions     map[string]LayoutPosition `json:"positions"`
	CreatedBy     string                    `json:"created_by"`
	CreatedAt     time.Time                 `json:"created_at"`
	UpdatedAt     time.Time                 `json:"updated_at"`
}

func validLayoutPosition(position LayoutPosition) bool {
	return position.X >= -100000 && position.X <= 100000 && position.Y >= -100000 && position.Y <= 100000
}
func validLayoutName(name string) bool { return len(strings.TrimSpace(name)) >= 2 && len(name) <= 80 }
func decodeLayout(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		fail(w, 400, "invalid_json", "Invalid or oversized JSON body")
		return false
	}
	return true
}
func (a *App) assetExists(ctx context.Context, envID, assetID string) (bool, error) {
	s := a.DB.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer s.Close(ctx)
	result, err := s.Run(ctx, "MATCH (a:Asset {environment_id:$env,id:$asset}) RETURN a.id", map[string]any{"env": envID, "asset": assetID})
	if err != nil {
		return false, err
	}
	if !result.Next(ctx) {
		return false, result.Err()
	}
	return true, nil
}
func (a *App) registerLayoutRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/environments/{id}/layouts", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), "SELECT id,environment_id,name,positions,created_by,created_at,updated_at FROM graph_layouts WHERE environment_id=$1 ORDER BY lower(name),id", r.PathValue("id"))
		if err != nil {
			fail(w, 500, "database_error", "Could not list layouts")
			return
		}
		defer rows.Close()
		items := []GraphLayout{}
		for rows.Next() {
			var item GraphLayout
			var positions []byte
			if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &positions, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
				fail(w, 500, "database_error", "Could not list layouts")
				return
			}
			if err = json.Unmarshal(positions, &item.Positions); err != nil {
				fail(w, 500, "database_error", "Invalid stored layout")
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			fail(w, 500, "database_error", "Could not list layouts")
			return
		}
		write(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/environments/{id}/layouts", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input struct {
			Name      string                    `json:"name"`
			Positions map[string]LayoutPosition `json:"positions"`
		}
		if !decodeLayout(w, r, &input) {
			return
		}
		if !validLayoutName(input.Name) || input.Positions == nil || len(input.Positions) > 2000 {
			fail(w, 422, "invalid_layout", "Provide a name of 2 to 80 characters and at most 2000 positions")
			return
		}
		graph, err := a.graph(r.Context(), r.PathValue("id"))
		if err != nil {
			fail(w, 500, "graph_error", "Could not validate layout assets")
			return
		}
		known := make(map[string]bool, len(graph.Assets))
		for _, asset := range graph.Assets {
			known[asset.ID] = true
		}
		for assetID, position := range input.Positions {
			if !known[assetID] || !validLayoutPosition(position) {
				fail(w, 422, "invalid_layout", "Positions must reference assets in the environment and stay within coordinate bounds")
				return
			}
		}
		encoded, _ := json.Marshal(input.Positions)
		item := GraphLayout{ID: "layout-" + id(), EnvironmentID: r.PathValue("id"), Name: strings.TrimSpace(input.Name), Positions: input.Positions, CreatedBy: principal(r).ID}
		err = a.Auth.Pool.QueryRow(r.Context(), "INSERT INTO graph_layouts(id,environment_id,name,positions,created_by) VALUES($1,$2,$3,$4,$5) RETURNING created_at,updated_at", item.ID, item.EnvironmentID, item.Name, encoded, item.CreatedBy).Scan(&item.CreatedAt, &item.UpdatedAt)
		if databaseConflict(err) {
			fail(w, 409, "layout_exists", "A layout with that name already exists")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not create layout")
			return
		}
		write(w, 201, item)
	})
	mux.HandleFunc("PATCH /api/v1/environments/{id}/layouts/{layoutID}/assets/{assetID}/position", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var position struct {
			X *int `json:"x"`
			Y *int `json:"y"`
		}
		if !decode(w, r, &position) {
			return
		}
		if position.X == nil || position.Y == nil || !validLayoutPosition(LayoutPosition{*position.X, *position.Y}) {
			fail(w, 422, "invalid_position", "x and y must be between -100000 and 100000")
			return
		}
		exists, err := a.assetExists(r.Context(), r.PathValue("id"), r.PathValue("assetID"))
		if err != nil {
			fail(w, 500, "graph_error", "Could not check asset")
			return
		}
		if !exists {
			fail(w, 404, "not_found", "Asset not found")
			return
		}
		encoded, _ := json.Marshal(LayoutPosition{*position.X, *position.Y})
		command, err := a.Auth.Pool.Exec(r.Context(), "UPDATE graph_layouts SET positions=jsonb_set(positions,ARRAY[$3::text],$4::jsonb,true),updated_at=now() WHERE environment_id=$1 AND id=$2", r.PathValue("id"), r.PathValue("layoutID"), r.PathValue("assetID"), encoded)
		if err != nil {
			fail(w, 500, "database_error", "Could not save position")
			return
		}
		if command.RowsAffected() == 0 {
			fail(w, 404, "not_found", "Layout not found")
			return
		}
		write(w, 200, map[string]any{"id": r.PathValue("assetID"), "layout_id": r.PathValue("layoutID"), "x": *position.X, "y": *position.Y})
	})
	mux.HandleFunc("DELETE /api/v1/environments/{id}/layouts/{layoutID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		command, err := a.Auth.Pool.Exec(r.Context(), "DELETE FROM graph_layouts WHERE environment_id=$1 AND id=$2", r.PathValue("id"), r.PathValue("layoutID"))
		if err != nil {
			fail(w, 500, "database_error", "Could not delete layout")
			return
		}
		if command.RowsAffected() == 0 {
			fail(w, 404, "not_found", "Layout not found")
			return
		}
		write(w, 200, map[string]string{"status": "deleted"})
	})
}
