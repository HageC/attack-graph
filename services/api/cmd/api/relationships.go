package main

import (
	"net/http"
	"strings"
)

type TopologyInput struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}
type TransitionInput struct {
	Source               string  `json:"source"`
	Target               string  `json:"target"`
	Reason               string  `json:"reason"`
	Likelihood           float64 `json:"likelihood"`
	RequiredCapability   string  `json:"required_capability"`
	GrantsCapability     string  `json:"grants_capability"`
	RequiredRelationship string  `json:"required_relationship"`
	VulnerabilityID      string  `json:"vulnerability_id"`
}

var topologyKinds = map[string]bool{"CAN_REACH": true, "HAS_ACCESS_TO": true, "TRUSTS": true, "DEPENDS_ON": true}
var capabilityKinds = map[string]bool{"foothold": true, "identity": true, "operator": true, "service_identity": true, "data_access": true}

func validTopology(v TopologyInput) bool {
	return v.Source != "" && v.Target != "" && v.Source != v.Target && topologyKinds[v.Kind]
}
func validTransition(v TransitionInput) bool {
	return v.Source != "" && v.Target != "" && v.Source != v.Target && len(strings.TrimSpace(v.Reason)) >= 12 && len(v.Reason) <= 200 && v.Likelihood > 0 && v.Likelihood <= 1 && topologyKinds[v.RequiredRelationship] && capabilityKinds[v.RequiredCapability] && capabilityKinds[v.GrantsCapability] && v.VulnerabilityID != ""
}

func (a *App) registerRelationshipRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/environments/{id}/relationships", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input TopologyInput
		if !decode(w, r, &input) {
			return
		}
		if !validTopology(input) {
			fail(w, 422, "invalid_relationship", "Choose distinct assets and a supported relationship type")
			return
		}
		generated := "rel-" + id()
		query := "MATCH (a:Asset {environment_id:$env,id:$source}),(b:Asset {environment_id:$env,id:$target}) MERGE (a)-[r:" + input.Kind + "]->(b) ON CREATE SET r.id=$id RETURN r.id"
		values, e := a.graphWrite(r.Context(), r.PathValue("id"), query, map[string]any{"env": r.PathValue("id"), "source": input.Source, "target": input.Target, "id": generated})
		if e != nil {
			fail(w, 500, "graph_error", "Could not create relationship")
			return
		}
		if values == nil {
			fail(w, 404, "not_found", "Source or target asset not found")
			return
		}
		actual, _ := values[0].(string)
		status := http.StatusOK
		if actual == generated {
			status = http.StatusCreated
		}
		write(w, status, Edge{ID: actual, Source: input.Source, Target: input.Target, Kind: input.Kind})
	})
	mux.HandleFunc("POST /api/v1/environments/{id}/transitions", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		var input TransitionInput
		if !decode(w, r, &input) {
			return
		}
		if !validTransition(input) {
			fail(w, 422, "invalid_transition", "Provide distinct assets, a reason, likelihood (0,1], supported capabilities and relationship, and a source vulnerability")
			return
		}
		generated := "tr-" + id()
		query := "MATCH (a:Asset {environment_id:$env,id:$source}),(b:Asset {environment_id:$env,id:$target}) MATCH (a)-[:CONTAINS_VULNERABILITY]->(v:Vulnerability {environment_id:$env,id:$vulnerability}) WHERE coalesce(v.state,'active')='active' MATCH (a)-[:" + input.RequiredRelationship + "]->(b) MERGE (a)-[t:TRANSITION {vulnerability_id:$vulnerability,required_capability:$required,grants_capability:$grants}]->(b) ON CREATE SET t.id=$id,t.reason=$reason,t.likelihood=$likelihood,t.required_relationship=$relationship,t.blocked=false RETURN t.id"
		values, e := a.graphWrite(r.Context(), r.PathValue("id"), query, map[string]any{"env": r.PathValue("id"), "source": input.Source, "target": input.Target, "vulnerability": input.VulnerabilityID, "required": input.RequiredCapability, "grants": input.GrantsCapability, "id": generated, "reason": input.Reason, "likelihood": input.Likelihood, "relationship": input.RequiredRelationship})
		if e != nil {
			fail(w, 500, "graph_error", "Could not create transition")
			return
		}
		if values == nil {
			fail(w, 422, "preconditions_unsatisfied", "A matching topology relationship and active source vulnerability are required")
			return
		}
		actual, _ := values[0].(string)
		status := http.StatusOK
		if actual == generated {
			status = http.StatusCreated
		}
		write(w, status, Edge{ID: actual, Source: input.Source, Target: input.Target, Kind: "TRANSITION", Reason: input.Reason, Likelihood: input.Likelihood, RequiredCapability: input.RequiredCapability, GrantsCapability: input.GrantsCapability, RequiredRelationship: input.RequiredRelationship, VulnerabilityID: input.VulnerabilityID})
	})
}
