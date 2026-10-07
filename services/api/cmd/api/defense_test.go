package main

import "testing"

func TestValidDefenseComparisonBounds(t *testing.T) {
	seed := int64(42)
	input := DefenseComparisonConfig{SimulationConfig: SimulationConfig{
		SnapshotID: "snapshot-1", StartAssetID: "ws-01", TargetAssetID: "db-01",
		Seed: &seed, DurationSeconds: 300, MaxSteps: 12,
		DetectionCoverage: 0.25, ControlEffectiveness: 0,
	}, Iterations: 200, ProposedControlEffectiveness: 0.5, ProposedDetectionCoverage: 0.75}
	if !validDefenseComparison(input) {
		t.Fatal("valid comparison rejected")
	}
	input.Iterations = 1001
	if validDefenseComparison(input) {
		t.Fatal("unbounded comparison accepted")
	}
	input.Iterations = 20
	input.ProposedControlEffectiveness = 1.1
	if validDefenseComparison(input) {
		t.Fatal("invalid proposed control accepted")
	}
}
