package main

import "testing"

func TestTelemetryClassification(t *testing.T) {
	cases := []struct { kind, result, eventType, truth string }{
		{"simulation_started", "started", "scenario_started", "scenario"},
		{"transition_attempt", "succeeded", "suspicious_access_attempt", "adversarial"},
		{"transition_attempt", "prevented", "control_block", "adversarial"},
		{"detection", "observed", "endpoint_alert", "control"},
		{"target_reached", "reached", "sensitive_resource_access", "adversarial"},
	}
	for _, item := range cases {
		gotType, gotTruth := telemetryClassification(simulationTelemetrySource{EventType:item.kind,Result:item.result})
		if gotType!=item.eventType || gotTruth!=item.truth { t.Fatalf("%s/%s: got %s/%s",item.kind,item.result,gotType,gotTruth) }
	}
}

func TestDetectionRuleValidation(t *testing.T) {
	rule:=DetectionRule{Name:"Observed endpoint alert",EventType:"endpoint_alert",MinSeverity:3,AssetID:"ws-01"}
	if !validDetectionRule(rule) { t.Fatal("valid rule rejected") }
	rule.AssetID="other asset"
	if validDetectionRule(rule) { t.Fatal("invalid asset filter accepted") }
	rule.AssetID=""
	rule.EventType="arbitrary_code"
	if validDetectionRule(rule) { t.Fatal("unsupported type accepted") }
}
