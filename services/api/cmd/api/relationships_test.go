package main

import "testing"

func TestRelationshipValidation(t *testing.T) {
	if !validTopology(TopologyInput{Source: "a", Target: "b", Kind: "CAN_REACH"}) {
		t.Fatal("valid topology rejected")
	}
	for _, kind := range []string{"TRANSITION", "CAN_REACH] DELETE n //", ""} {
		if validTopology(TopologyInput{Source: "a", Target: "b", Kind: kind}) {
			t.Errorf("accepted unsafe kind %q", kind)
		}
	}
	if validTopology(TopologyInput{Source: "a", Target: "a", Kind: "TRUSTS"}) {
		t.Fatal("self edge accepted")
	}
}
func TestTransitionValidation(t *testing.T) {
	base := TransitionInput{Source: "a", Target: "b", Reason: "Modeled access gap", Likelihood: .5, RequiredCapability: "foothold", GrantsCapability: "operator", RequiredRelationship: "CAN_REACH", VulnerabilityID: "AG-1"}
	if !validTransition(base) {
		t.Fatal("valid transition rejected")
	}
	base.Likelihood = 1.2
	if validTransition(base) {
		t.Fatal("invalid likelihood accepted")
	}
	base.Likelihood = .5
	base.RequiredRelationship = "TRANSITION"
	if validTransition(base) {
		t.Fatal("transition used as topology")
	}
}
