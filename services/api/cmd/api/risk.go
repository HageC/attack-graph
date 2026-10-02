package main

import "math"

// scoreAssets is an interpretable synthetic ranking, not a calibrated breach probability.
// It combines local weakness severity, criticality, modeled incoming reachability,
// unblocked outgoing transitions, downstream value and blocking controls.
func scoreAssets(graph *Graph, vulnerabilities []Vulnerability) {
	byID := make(map[string]*Asset, len(graph.Assets))
	maxCVSS := make(map[string]float64)
	activeWeakness := make(map[string]string)
	incoming := make(map[string]int)
	dmzIncoming := make(map[string]int)
	outgoing := make(map[string]int)
	blocked := make(map[string]int)
	downstream := make(map[string]int)
	for i := range graph.Assets {
		byID[graph.Assets[i].ID] = &graph.Assets[i]
	}
	for _, v := range vulnerabilities {
		if v.State == "mitigated" {
			continue
		}
		activeWeakness[v.ID] = v.AssetID
		if v.CVSS > maxCVSS[v.AssetID] {
			maxCVSS[v.AssetID] = v.CVSS
		}
	}
	for _, edge := range graph.Edges {
		source := byID[edge.Source]
		target := byID[edge.Target]
		if source == nil || target == nil {
			continue
		}
		if edge.Kind == "CAN_REACH" {
			incoming[target.ID]++
			if source.Segment == "DMZ" {
				dmzIncoming[target.ID]++
			}
		}
		if edge.Kind == "TRANSITION" {
			if edge.Blocked {
				blocked[source.ID]++
			} else if activeWeakness[edge.VulnerabilityID] == source.ID {
				outgoing[source.ID]++
				if target.Criticality > downstream[source.ID] {
					downstream[source.ID] = target.Criticality
				}
			}
		}
	}
	for i := range graph.Assets {
		asset := &graph.Assets[i]
		score := .35*maxCVSS[asset.ID]*10 + float64(asset.Criticality*8+incoming[asset.ID]*2+dmzIncoming[asset.ID]*12+outgoing[asset.ID]*3+downstream[asset.ID]*2-blocked[asset.ID]*6)
		asset.Risk = int(math.Round(math.Max(0, math.Min(100, score))))
	}
}
