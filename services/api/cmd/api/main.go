package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

//go:embed openapi.yaml
var openapiSpec []byte

type Asset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Segment     string `json:"segment"`
	IP          string `json:"ip"`
	Criticality int    `json:"criticality"`
	Risk        int    `json:"risk"`
	X           int    `json:"x"`
	Y           int    `json:"y"`
}
type Edge struct {
	ID                   string  `json:"id"`
	Source               string  `json:"source"`
	Target               string  `json:"target"`
	Kind                 string  `json:"kind"`
	Reason               string  `json:"reason,omitempty"`
	Likelihood           float64 `json:"likelihood"`
	RequiredCapability   string  `json:"required_capability,omitempty"`
	GrantsCapability     string  `json:"grants_capability,omitempty"`
	VulnerabilityID      string  `json:"vulnerability_id,omitempty"`
	RequiredRelationship string  `json:"required_relationship,omitempty"`
	Blocked              bool    `json:"blocked,omitempty"`
}
type Graph struct {
	Assets []Asset `json:"assets"`
	Edges  []Edge  `json:"edges"`
}
type App struct {
	DB            neo4j.DriverWithContext
	Auth          *AuthStore
	Client        *http.Client
	SimulationURL string
}

var seedAssets = []Asset{
	{"ws-01", "Maya Chen · Workstation", "workstation", "Corporate", "10.20.10.24", 2, 58, 80, 200},
	{"ws-02", "Operations Workstation", "workstation", "Corporate", "10.20.10.38", 2, 35, 80, 380},
	{"id-01", "Northstar Identity", "identity", "Identity", "10.20.20.10", 4, 72, 370, 80},
	{"app-01", "Payments API", "application", "Applications", "10.20.30.12", 4, 81, 370, 280},
	{"app-02", "Customer Portal", "application", "DMZ", "10.20.40.15", 3, 88, 370, 470},
	{"svc-01", "Payments Service Account", "service_account", "Identity", "10.20.20.44", 3, 77, 660, 100},
	{"db-01", "Customer Ledger", "database", "Data", "10.20.50.10", 5, 94, 660, 310},
	{"db-02", "Analytics Warehouse", "database", "Data", "10.20.50.28", 4, 65, 660, 500},
	{"fw-01", "Internal Firewall", "firewall", "Core", "10.20.0.1", 4, 25, 960, 220},
	{"edr-01", "Endpoint Detection", "monitoring", "Security", "10.20.60.8", 4, 16, 960, 410},
}
var seedEdges = []Edge{
	{ID: "top-01", Source: "ws-01", Target: "app-01", Kind: "CAN_REACH"},
	{ID: "top-02", Source: "app-01", Target: "db-01", Kind: "CAN_REACH"},
	{ID: "top-03", Source: "app-02", Target: "app-01", Kind: "CAN_REACH"},
	{ID: "top-04", Source: "svc-01", Target: "db-02", Kind: "HAS_ACCESS_TO"},
	{ID: "top-05", Source: "ws-01", Target: "id-01", Kind: "CAN_REACH"},
	{ID: "top-06", Source: "id-01", Target: "app-01", Kind: "HAS_ACCESS_TO"},
	{ID: "top-07", Source: "app-01", Target: "svc-01", Kind: "HAS_ACCESS_TO"},
	{ID: "top-08", Source: "svc-01", Target: "db-01", Kind: "HAS_ACCESS_TO"},
	{ID: "tr-01", Source: "ws-01", Target: "id-01", Kind: "TRANSITION", Reason: "Cached synthetic session permits identity access", Likelihood: .68, RequiredCapability: "foothold", GrantsCapability: "identity", VulnerabilityID: "AG-001"},
	{ID: "tr-02", Source: "id-01", Target: "app-01", Kind: "TRANSITION", Reason: "Excessive application operator permission", Likelihood: .72, RequiredCapability: "identity", GrantsCapability: "operator", VulnerabilityID: "AG-002", RequiredRelationship: "HAS_ACCESS_TO"},
	{ID: "tr-03", Source: "app-01", Target: "db-01", Kind: "TRANSITION", Reason: "Application identity has broad ledger access", Likelihood: .64, RequiredCapability: "operator", GrantsCapability: "data_access", VulnerabilityID: "AG-003"},
	{ID: "tr-04", Source: "app-02", Target: "app-01", Kind: "TRANSITION", Reason: "Modeled exposed service and permissive internal route", Likelihood: .55, RequiredCapability: "foothold", GrantsCapability: "operator", VulnerabilityID: "AG-004"},
	{ID: "tr-05", Source: "app-01", Target: "svc-01", Kind: "TRANSITION", Reason: "Service account role is available to the application", Likelihood: .78, RequiredCapability: "operator", GrantsCapability: "service_identity", VulnerabilityID: "AG-003", RequiredRelationship: "HAS_ACCESS_TO"},
	{ID: "tr-06", Source: "svc-01", Target: "db-01", Kind: "TRANSITION", Reason: "Service account can query the sensitive ledger", Likelihood: .8, RequiredCapability: "service_identity", GrantsCapability: "data_access", VulnerabilityID: "AG-005", RequiredRelationship: "HAS_ACCESS_TO"},
	{ID: "tr-07", Source: "svc-01", Target: "db-02", Kind: "TRANSITION", Reason: "Service account has excessive warehouse grants", Likelihood: .82, RequiredCapability: "service_identity", GrantsCapability: "data_access", VulnerabilityID: "AG-005", RequiredRelationship: "HAS_ACCESS_TO"},
	{ID: "tr-08", Source: "ws-02", Target: "db-01", Kind: "TRANSITION", Reason: "Firewall blocks direct database access", Likelihood: 0, RequiredCapability: "foothold", Blocked: true},
}

func ensureGraphConstraints(ctx context.Context, db neo4j.DriverWithContext) error {
	session := db.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	constraint, err := session.Run(ctx, "CREATE CONSTRAINT asset_key IF NOT EXISTS FOR (a:Asset) REQUIRE (a.environment_id, a.id) IS UNIQUE", nil)
	if err != nil {
		return err
	}
	if _, err = constraint.Consume(ctx); err != nil {
		return err
	}
	lockConstraint, err := session.Run(ctx, "CREATE CONSTRAINT environment_lock_key IF NOT EXISTS FOR (l:EnvironmentLock) REQUIRE l.environment_id IS UNIQUE", nil)
	if err != nil {
		return err
	}
	if _, err = lockConstraint.Consume(ctx); err != nil {
		return err
	}
	return nil
}
func seed(ctx context.Context, db neo4j.DriverWithContext) error {
	session := db.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	var err error
	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		for _, a := range seedAssets {
			if _, e := tx.Run(ctx, "MERGE (a:Asset {environment_id:'northstar', id:$id}) ON CREATE SET a += $props", map[string]any{"id": a.ID, "props": map[string]any{"name": a.Name, "type": a.Type, "segment": a.Segment, "ip": a.IP, "criticality": a.Criticality, "risk": a.Risk, "x": a.X, "y": a.Y}}); e != nil {
				return nil, e
			}
		}
		for _, e := range seedEdges {
			query := "MATCH (a:Asset {environment_id:'northstar',id:$source}),(b:Asset {environment_id:'northstar',id:$target}) MERGE (a)-[r:" + e.Kind + " {id:$id}]->(b) ON CREATE SET r += $props SET r.required_relationship = coalesce(r.required_relationship, $relationship)"
			relationship := e.RequiredRelationship
			if relationship == "" && e.Kind == "TRANSITION" {
				relationship = "CAN_REACH"
			}
			_, x := tx.Run(ctx, query, map[string]any{"source": e.Source, "target": e.Target, "id": e.ID, "relationship": relationship, "props": map[string]any{"reason": e.Reason, "likelihood": e.Likelihood, "required_capability": e.RequiredCapability, "grants_capability": e.GrantsCapability, "required_relationship": relationship, "vulnerability_id": e.VulnerabilityID, "blocked": e.Blocked}})
			if x != nil {
				return nil, x
			}
		}
		if _, e := tx.Run(ctx, "MATCH (:Asset {environment_id:'northstar',id:'app-01'})-[r:TRANSITION {id:'tr-05'}]->(:Asset {environment_id:'northstar',id:'svc-01'}) WHERE r.vulnerability_id='AG-005' SET r.vulnerability_id='AG-003'", nil); e != nil {
			return nil, e
		}
		return nil, nil
	})
	return err
}
func (a *App) graph(ctx context.Context, id string) (Graph, error) {
	session := a.DB.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	g, _, err := loadGraph(ctx, func(ctx context.Context, query string, params map[string]any) (neo4j.ResultWithContext, error) {
		return session.Run(ctx, query, params)
	}, id)
	return g, err
}

type graphQueryRunner func(context.Context, string, map[string]any) (neo4j.ResultWithContext, error)

func loadGraph(ctx context.Context, runner graphQueryRunner, id string) (Graph, []Vulnerability, error) {
	g := Graph{Assets: []Asset{}, Edges: []Edge{}}
	result, err := runner(ctx, "MATCH (a:Asset {environment_id:$id}) RETURN a ORDER BY a.id", map[string]any{"id": id})
	if err != nil {
		return g, nil, err
	}
	for result.Next(ctx) {
		m := result.Record().Values[0].(neo4j.Node).Props
		g.Assets = append(g.Assets, Asset{ID: str(m, "id"), Name: str(m, "name"), Type: str(m, "type"), Segment: str(m, "segment"), IP: str(m, "ip"), Criticality: num(m, "criticality"), Risk: num(m, "risk"), X: num(m, "x"), Y: num(m, "y")})
	}
	if err = result.Err(); err != nil {
		return g, nil, err
	}
	result, err = runner(ctx, "MATCH (a:Asset {environment_id:$id})-[r]->(b:Asset {environment_id:$id}) RETURN a.id,b.id,type(r),r ORDER BY r.id", map[string]any{"id": id})
	if err != nil {
		return g, nil, err
	}
	for result.Next(ctx) {
		v := result.Record().Values
		m := v[3].(neo4j.Relationship).Props
		relationship := str(m, "required_relationship")
		if relationship == "" && v[2].(string) == "TRANSITION" {
			relationship = "CAN_REACH"
		}
		g.Edges = append(g.Edges, Edge{ID: str(m, "id"), Source: v[0].(string), Target: v[1].(string), Kind: v[2].(string), Reason: str(m, "reason"), Likelihood: decimal(m, "likelihood"), RequiredCapability: str(m, "required_capability"), GrantsCapability: str(m, "grants_capability"), RequiredRelationship: relationship, VulnerabilityID: str(m, "vulnerability_id"), Blocked: flag(m, "blocked")})
	}
	if err = result.Err(); err != nil {
		return g, nil, err
	}
	vulnerabilities, err := loadVulnerabilities(ctx, runner, id)
	if err != nil {
		return g, nil, err
	}
	scoreAssets(&g, vulnerabilities)
	return g, vulnerabilities, nil
}
func str(m map[string]any, k string) string      { v, _ := m[k].(string); return v }
func num(m map[string]any, k string) int         { v, _ := m[k].(int64); return int(v) }
func decimal(m map[string]any, k string) float64 { v, _ := m[k].(float64); return v }
func flag(m map[string]any, k string) bool       { v, _ := m[k].(bool); return v }
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	write(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func main() {
	ctx := context.Background()
	auth, err := initPostgres(ctx)
	if err != nil {
		panic(err)
	}
	defer auth.Pool.Close()
	uri := os.Getenv("NEO4J_URI")
	if uri == "" {
		uri = "bolt://localhost:7687"
	}
	pass := os.Getenv("NEO4J_PASSWORD")
	if pass == "" {
		pass = "attackgraph-local-only"
	}
	db, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth("neo4j", pass, ""))
	if err != nil {
		panic(err)
	}
	defer db.Close(ctx)
	for i := 0; i < 30; i++ {
		if err = db.VerifyConnectivity(ctx); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		panic(err)
	}
	if err = ensureGraphConstraints(ctx, db); err != nil {
		panic(err)
	}
	if os.Getenv("DEMO_MODE") == "true" {
		if err = seed(ctx, db); err != nil {
			panic(err)
		}
		if err = seedVulnerabilities(ctx, db); err != nil {
			panic(err)
		}
	}
	sim := os.Getenv("SIMULATION_URL")
	if sim == "" {
		sim = "http://localhost:8000"
	}
	a := &App{DB: db, Auth: auth, Client: &http.Client{Timeout: 10 * time.Second}, SimulationURL: sim}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/v1/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		_, _ = w.Write(openapiSpec)
	})
	auth.registerAuthRoutes(mux)
	mux.HandleFunc("GET /api/v1/environments", a.listEnvironments)
	mux.HandleFunc("GET /api/v1/environments/{id}/graph", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !auth.authorize(w, r, id, false) {
			return
		}
		g, e := a.graph(r.Context(), id)
		if e != nil {
			fail(w, 500, "graph_error", e.Error())
			return
		}
		write(w, 200, g)
	})
	a.registerEditingRoutes(mux)
	a.registerRelationshipRoutes(mux)
	a.registerSnapshotRoutes(mux)
	a.registerManagementRoutes(mux)
	a.registerLayoutRoutes(mux)
	a.registerSimulationRoutes(mux)
	a.registerSimulationJobRoutes(mux)
	a.registerSimulationStreamRoutes(mux)
	a.registerDetectionRoutes(mux)
	a.registerDefenseRoutes(mux)
	a.registerSOCRoutes(mux)
	a.registerReportRoutes(mux)
	go a.runSimulationJobs(ctx)
	mux.HandleFunc("POST /api/v1/attack-paths/analyze", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var input struct {
			EnvironmentID       string   `json:"environment_id"`
			SnapshotID          string   `json:"snapshot_id"`
			StartAssetID        string   `json:"start_asset_id"`
			TargetAssetID       string   `json:"target_asset_id"`
			MaxDepth            int      `json:"max_depth"`
			InitialCapabilities []string `json:"initial_capabilities"`
		}
		if e := json.NewDecoder(r.Body).Decode(&input); e != nil {
			fail(w, 400, "invalid_json", "Invalid request body")
			return
		}
		if !auth.authorize(w, r, input.EnvironmentID, false) {
			return
		}
		if input.MaxDepth == 0 {
			input.MaxDepth = 6
		}
		if input.MaxDepth < 1 || input.MaxDepth > 12 {
			fail(w, 422, "invalid_depth", "max_depth must be between 1 and 12")
			return
		}
		if len(input.InitialCapabilities) > 4 {
			fail(w, 422, "invalid_capabilities", "Too many initial capabilities")
			return
		}
		allowed := map[string]bool{"foothold": true, "identity": true, "operator": true, "service_identity": true}
		for _, capability := range input.InitialCapabilities {
			if !allowed[capability] {
				fail(w, 422, "invalid_capabilities", "Unsupported initial capability")
				return
			}
		}
		if len(input.InitialCapabilities) == 0 {
			input.InitialCapabilities = []string{"foothold"}
		}
		var g Graph
		var vulnerabilities []Vulnerability
		if input.SnapshotID == "" {
			var e error
			g, e = a.graph(r.Context(), input.EnvironmentID)
			if e != nil {
				fail(w, 500, "graph_error", "Could not load graph")
				return
			}
			vulnerabilities, e = a.vulnerabilities(r.Context(), input.EnvironmentID)
			if e != nil {
				fail(w, 500, "graph_error", "Could not load vulnerabilities")
				return
			}
		} else {
			snapshot, e := a.snapshot(r.Context(), input.EnvironmentID, input.SnapshotID)
			if errors.Is(e, pgx.ErrNoRows) {
				fail(w, 404, "not_found", "Snapshot not found")
				return
			}
			if e != nil {
				fail(w, 500, "database_error", "Could not load snapshot")
				return
			}
			if e = json.Unmarshal(snapshot.Graph, &g); e != nil {
				fail(w, 500, "snapshot_error", "Invalid snapshot graph")
				return
			}
			if e = json.Unmarshal(snapshot.Vulnerabilities, &vulnerabilities); e != nil {
				fail(w, 500, "snapshot_error", "Invalid snapshot vulnerabilities")
				return
			}
		}
		payload := map[string]any{"assets": g.Assets, "transitions": filterTransitions(g.Edges), "relationships": filterTopology(g.Edges), "vulnerabilities": vulnerabilities, "start_asset_id": input.StartAssetID, "target_asset_id": input.TargetAssetID, "max_depth": input.MaxDepth, "initial_capabilities": input.InitialCapabilities}
		body, _ := json.Marshal(payload)
		req, e := http.NewRequestWithContext(r.Context(), "POST", a.SimulationURL+"/analyze", bytes.NewReader(body))
		if e != nil {
			fail(w, 500, "internal", e.Error())
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, e := a.Client.Do(req)
		if e != nil {
			fail(w, 502, "simulation_unavailable", e.Error())
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != 200 {
			fail(w, 422, "analysis_failed", string(data))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		auth.middleware(mux).ServeHTTP(w, r)
	})
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	slog.Info("api listening", "port", port)
	if e := http.ListenAndServe(":"+port, handler); !errors.Is(e, http.ErrServerClosed) {
		panic(e)
	}
}
func filterTransitions(edges []Edge) []Edge {
	out := []Edge{}
	for _, e := range edges {
		if e.Kind == "TRANSITION" {
			out = append(out, e)
		}
	}
	return out
}
func filterTopology(edges []Edge) []Edge {
	out := []Edge{}
	for _, e := range edges {
		if e.Kind != "TRANSITION" {
			out = append(out, e)
		}
	}
	return out
}
