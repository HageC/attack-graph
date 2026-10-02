package main

import "testing"

func TestRiskRespondsToWeaknessAndControl(t *testing.T) {
	graph := Graph{Assets: []Asset{{ID: "a", Criticality: 2, Segment: "DMZ"}, {ID: "b", Criticality: 5, Segment: "Data"}}, Edges: []Edge{{Source: "a", Target: "b", Kind: "CAN_REACH"}, {Source: "a", Target: "b", Kind: "TRANSITION", VulnerabilityID: "v"}}}
	scoreAssets(&graph, nil)
	base := graph.Assets[0].Risk
	scoreAssets(&graph, []Vulnerability{{ID: "v", AssetID: "a", CVSS: 8, State: "active"}})
	if graph.Assets[0].Risk <= base {
		t.Fatal("weakness did not raise risk")
	}
	graph.Edges[1].Blocked = true
	scoreAssets(&graph, []Vulnerability{{ID: "v", AssetID: "a", CVSS: 8, State: "active"}})
	if graph.Assets[0].Risk >= base+28 {
		t.Fatal("blocking transition did not lower risk")
	}
}

func TestMitigatedWeaknessLowersRisk(t *testing.T) {
	graph := Graph{Assets: []Asset{{ID: "a", Criticality: 2}, {ID: "b", Criticality: 5}}, Edges: []Edge{{Source: "a", Target: "b", Kind: "TRANSITION", VulnerabilityID: "v"}}}
	scoreAssets(&graph, []Vulnerability{{ID: "v", AssetID: "a", CVSS: 8, State: "active"}})
	active := graph.Assets[0].Risk
	scoreAssets(&graph, []Vulnerability{{ID: "v", AssetID: "a", CVSS: 8, State: "mitigated"}})
	if graph.Assets[0].Risk >= active {
		t.Fatal("mitigation did not lower risk")
	}
}
