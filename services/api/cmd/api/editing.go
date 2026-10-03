package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Vulnerability struct {
	ID          string  `json:"id"`
	AssetID     string  `json:"asset_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Mitigation  string  `json:"mitigation"`
	State       string  `json:"state"`
}

var demoVulnerabilities = []Vulnerability{
	{"AG-001", "ws-01", "Cached synthetic identity session", "Modeled workstation session grants identity context.", "high", 7.1, "Require fresh authentication for privileged tasks.", "active"},
	{"AG-002", "id-01", "Excessive operator permission", "Identity can administer the modeled payments application.", "high", 8.0, "Reduce operator grants to the minimum role.", "active"},
	{"AG-003", "app-01", "Broad ledger access", "Application identity can access sensitive ledger data.", "critical", 9.1, "Scope database permissions by service task.", "active"},
	{"AG-004", "app-02", "Exposed service weakness", "Synthetic portal weakness and permissive internal route.", "critical", 9.3, "Patch service and limit DMZ egress.", "active"},
	{"AG-005", "svc-01", "Overprivileged service account", "Shared service identity has access to multiple data stores.", "high", 8.6, "Split identities and remove unused grants.", "active"},
}

func seedVulnerabilities(ctx context.Context, db neo4j.DriverWithContext) error {
	s := db.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer s.Close(ctx)
	for _, v := range demoVulnerabilities {
		result, e := s.Run(ctx, "MATCH (a:Asset {environment_id:'northstar',id:$asset}) MERGE (v:Vulnerability {environment_id:'northstar',id:$id}) ON CREATE SET v.title=$title,v.description=$description,v.severity=$severity,v.cvss=$cvss,v.mitigation=$mitigation SET v.state=coalesce(v.state,'active') MERGE (a)-[:CONTAINS_VULNERABILITY]->(v)", map[string]any{"asset": v.AssetID, "id": v.ID, "title": v.Title, "description": v.Description, "severity": v.Severity, "cvss": v.CVSS, "mitigation": v.Mitigation})
		if e != nil {
			return e
		}
		if _, e = result.Consume(ctx); e != nil {
			return e
		}
	}
	return nil
}

func id() string { var b [12]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func privateIP(value string) bool {
	ip, e := netip.ParseAddr(value)
	if e != nil || !ip.Is4() {
		return false
	}
	a := ip.As4()
	return a[0] == 10 || (a[0] == 172 && a[1] >= 16 && a[1] <= 31) || (a[0] == 192 && a[1] == 168)
}
func validAsset(a Asset) bool {
	types := map[string]bool{"workstation": true, "identity": true, "application": true, "service_account": true, "database": true, "firewall": true, "monitoring": true, "server": true, "router": true, "cloud": true}
	return len(strings.TrimSpace(a.Name)) >= 2 && len(a.Name) <= 80 && len(strings.TrimSpace(a.Segment)) >= 2 && len(a.Segment) <= 40 && types[a.Type] && privateIP(a.IP) && a.Criticality >= 1 && a.Criticality <= 5
}
func validVulnerability(v Vulnerability) bool {
	severity := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	return len(strings.TrimSpace(v.Title)) >= 3 && len(v.Title) <= 120 && len(v.Description) <= 1000 && len(v.Mitigation) <= 500 && severity[v.Severity] && v.CVSS >= 0 && v.CVSS <= 10
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "invalid_json", "Invalid or oversized JSON body")
		return false
	}
	return true
}
func environment(w http.ResponseWriter, r *http.Request) bool {
	store, _ := r.Context().Value(authKey{}).(*AuthStore)
	if store == nil {
		fail(w, 401, "unauthorized", "Sign in required")
		return false
	}
	return store.authorize(w, r, r.PathValue("id"), r.Method != "GET")
}

func (a *App) registerEditingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/environments/{id}/assets", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input Asset
		if !decode(w, r, &input) {
			return
		}
		if !validAsset(input) {
			fail(w, 422, "invalid_asset", "Provide a name, supported type, segment, RFC 1918 IPv4 address, and criticality from 1 to 5")
			return
		}
		input.ID = "asset-" + id()
		input.Risk = input.Criticality * 8
		input.X = 120
		input.Y = 120
		_, e := a.graphWrite(r.Context(), r.PathValue("id"), "CREATE (n:Asset {environment_id:$env,id:$id,name:$name,type:$type,segment:$segment,ip:$ip,criticality:$criticality,risk:$risk,x:$x,y:$y}) RETURN n.id", map[string]any{"env": r.PathValue("id"), "id": input.ID, "name": input.Name, "type": input.Type, "segment": input.Segment, "ip": input.IP, "criticality": input.Criticality, "risk": input.Risk, "x": input.X, "y": input.Y})
		if e != nil {
			fail(w, 500, "graph_error", "Could not create asset")
			return
		}
		write(w, 201, input)
	})
	mux.HandleFunc("PATCH /api/v1/environments/{id}/assets/{assetID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input Asset
		if !decode(w, r, &input) {
			return
		}
		if !validAsset(input) {
			fail(w, 422, "invalid_asset", "Provide a name, supported type, segment, RFC 1918 IPv4 address, and criticality from 1 to 5")
			return
		}
		input.ID = r.PathValue("assetID")
		values, e := a.graphWrite(r.Context(), r.PathValue("id"), "MATCH (n:Asset {environment_id:$env,id:$id}) SET n.name=$name,n.type=$type,n.segment=$segment,n.ip=$ip,n.criticality=$criticality RETURN n", map[string]any{"env": r.PathValue("id"), "id": input.ID, "name": input.Name, "type": input.Type, "segment": input.Segment, "ip": input.IP, "criticality": input.Criticality})
		if e != nil {
			fail(w, 500, "graph_error", "Could not update asset")
			return
		}
		if values == nil {
			fail(w, 404, "not_found", "Asset not found")
			return
		}
		m := values[0].(neo4j.Node).Props
		write(w, 200, Asset{ID: input.ID, Name: input.Name, Type: input.Type, Segment: input.Segment, IP: input.IP, Criticality: input.Criticality, Risk: num(m, "risk"), X: num(m, "x"), Y: num(m, "y")})
	})
	mux.HandleFunc("PATCH /api/v1/environments/{id}/assets/{assetID}/position", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input struct {
			X *int `json:"x"`
			Y *int `json:"y"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.X == nil || input.Y == nil || *input.X < -5000 || *input.X > 5000 || *input.Y < -5000 || *input.Y > 5000 {
			fail(w, 422, "invalid_position", "x and y must be between -5000 and 5000")
			return
		}
		values, e := a.graphWrite(r.Context(), r.PathValue("id"), "MATCH (n:Asset {environment_id:$env,id:$id}) SET n.x=$x,n.y=$y RETURN n.id", map[string]any{"env": r.PathValue("id"), "id": r.PathValue("assetID"), "x": *input.X, "y": *input.Y})
		if e != nil {
			fail(w, 500, "graph_error", "Could not save position")
			return
		}
		if values == nil {
			fail(w, 404, "not_found", "Asset not found")
			return
		}
		write(w, 200, map[string]any{"id": r.PathValue("assetID"), "x": *input.X, "y": *input.Y})
	})
	mux.HandleFunc("PATCH /api/v1/environments/{id}/transitions/{transitionID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input struct {
			Blocked *bool `json:"blocked"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Blocked == nil {
			fail(w, 422, "invalid_transition", "blocked is required")
			return
		}
		values, e := a.graphWrite(r.Context(), r.PathValue("id"), "MATCH (:Asset {environment_id:$env})-[t:TRANSITION {id:$id}]->(:Asset {environment_id:$env}) SET t.blocked=$blocked RETURN t.id", map[string]any{"env": r.PathValue("id"), "id": r.PathValue("transitionID"), "blocked": *input.Blocked})
		if e != nil {
			fail(w, 500, "graph_error", "Could not update transition")
			return
		}
		if values == nil {
			fail(w, 404, "not_found", "Transition not found")
			return
		}
		write(w, 200, map[string]any{"id": r.PathValue("transitionID"), "blocked": *input.Blocked})
	})
	mux.HandleFunc("GET /api/v1/environments/{id}/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		items, e := a.vulnerabilities(r.Context(), r.PathValue("id"))
		if e != nil {
			fail(w, 500, "graph_error", "Could not load vulnerabilities")
			return
		}
		write(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/environments/{id}/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var v Vulnerability
		if !decode(w, r, &v) {
			return
		}
		if !validVulnerability(v) || v.AssetID == "" {
			fail(w, 422, "invalid_vulnerability", "Provide an asset, title, severity and CVSS from 0 to 10")
			return
		}
		v.ID = "AG-" + id()
		v.State = "active"
		values, e := a.graphWrite(r.Context(), r.PathValue("id"), "MATCH (a:Asset {environment_id:$env,id:$asset}) CREATE (v:Vulnerability {environment_id:$env,id:$id,title:$title,description:$description,severity:$severity,cvss:$cvss,mitigation:$mitigation,state:'active'}) CREATE (a)-[:CONTAINS_VULNERABILITY]->(v) RETURN v.id", map[string]any{"env": r.PathValue("id"), "asset": v.AssetID, "id": v.ID, "title": v.Title, "description": v.Description, "severity": v.Severity, "cvss": v.CVSS, "mitigation": v.Mitigation})
		if e != nil {
			fail(w, 500, "graph_error", "Could not create vulnerability")
			return
		}
		if values == nil {
			fail(w, 404, "not_found", "Asset not found")
			return
		}
		write(w, 201, v)
	})
	mux.HandleFunc("PATCH /api/v1/environments/{id}/vulnerabilities/{vulnerabilityID}", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var v Vulnerability
		if !decode(w, r, &v) {
			return
		}
		if !validVulnerability(v) {
			fail(w, 422, "invalid_vulnerability", "Provide a title, severity and CVSS from 0 to 10")
			return
		}
		v.ID = r.PathValue("vulnerabilityID")
		values, e := a.graphWrite(r.Context(), r.PathValue("id"), "MATCH (a:Asset {environment_id:$env})-[:CONTAINS_VULNERABILITY]->(v:Vulnerability {environment_id:$env,id:$id}) SET v.title=$title,v.description=$description,v.severity=$severity,v.cvss=$cvss,v.mitigation=$mitigation RETURN a.id,coalesce(v.state,'active')", map[string]any{"env": r.PathValue("id"), "id": v.ID, "title": v.Title, "description": v.Description, "severity": v.Severity, "cvss": v.CVSS, "mitigation": v.Mitigation})
		if e != nil {
			fail(w, 500, "graph_error", "Could not update vulnerability")
			return
		}
		if values == nil {
			fail(w, 404, "not_found", "Vulnerability not found")
			return
		}
		v.AssetID = values[0].(string)
		v.State = values[1].(string)
		write(w, 200, v)
	})
	mux.HandleFunc("PATCH /api/v1/environments/{id}/vulnerabilities/{vulnerabilityID}/state", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input struct {
			State string `json:"state"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.State != "active" && input.State != "mitigated" {
			fail(w, 422, "invalid_state", "state must be active or mitigated")
			return
		}
		values, e := a.graphWrite(r.Context(), r.PathValue("id"), "MATCH (:Asset {environment_id:$env})-[:CONTAINS_VULNERABILITY]->(v:Vulnerability {environment_id:$env,id:$id}) SET v.state=$state RETURN v.id", map[string]any{"env": r.PathValue("id"), "id": r.PathValue("vulnerabilityID"), "state": input.State})
		if e != nil {
			fail(w, 500, "graph_error", "Could not update vulnerability state")
			return
		}
		if values == nil {
			fail(w, 404, "not_found", "Vulnerability not found")
			return
		}
		write(w, 200, map[string]string{"id": r.PathValue("vulnerabilityID"), "state": input.State})
	})
}
func (a *App) vulnerabilities(ctx context.Context, envID string) ([]Vulnerability, error) {
	s := a.DB.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer s.Close(ctx)
	return loadVulnerabilities(ctx, func(ctx context.Context, query string, params map[string]any) (neo4j.ResultWithContext, error) {
		return s.Run(ctx, query, params)
	}, envID)
}
func loadVulnerabilities(ctx context.Context, runner graphQueryRunner, envID string) ([]Vulnerability, error) {
	result, e := runner(ctx, "MATCH (a:Asset {environment_id:$env})-[:CONTAINS_VULNERABILITY]->(v:Vulnerability {environment_id:$env}) RETURN a.id,v ORDER BY v.id", map[string]any{"env": envID})
	if e != nil {
		return nil, e
	}
	items := []Vulnerability{}
	for result.Next(ctx) {
		values := result.Record().Values
		m := values[1].(neo4j.Node).Props
		state := str(m, "state")
		if state == "" {
			state = "active"
		}
		items = append(items, Vulnerability{ID: str(m, "id"), AssetID: values[0].(string), Title: str(m, "title"), Description: str(m, "description"), Severity: str(m, "severity"), CVSS: decimal(m, "cvss"), Mitigation: str(m, "mitigation"), State: state})
	}
	return items, result.Err()
}
