package main

import "testing"

func TestPrivateIP(t *testing.T) {
	for _, input := range []string{"10.20.10.1", "172.16.4.1", "172.31.255.1", "192.168.1.1"} {
		if !privateIP(input) {
			t.Errorf("rejected RFC 1918 address %s", input)
		}
	}
	for _, input := range []string{"8.8.8.8", "172.32.0.1", "127.0.0.1", "::1", "bad"} {
		if privateIP(input) {
			t.Errorf("accepted non-private address %s", input)
		}
	}
}
func TestAssetValidation(t *testing.T) {
	a := Asset{Name: "Synthetic server", Type: "server", Segment: "Corporate", IP: "10.0.0.4", Criticality: 3}
	if !validAsset(a) {
		t.Fatal("valid asset rejected")
	}
	a.IP = "203.0.113.4"
	if validAsset(a) {
		t.Fatal("public IP accepted")
	}
	a.IP = "10.0.0.4"
	a.Type = "unknown"
	if validAsset(a) {
		t.Fatal("unknown type accepted")
	}
}
func TestVulnerabilityValidation(t *testing.T) {
	v := Vulnerability{Title: "Abstract weakness", Severity: "high", CVSS: 7.5}
	if !validVulnerability(v) {
		t.Fatal("valid weakness rejected")
	}
	v.CVSS = 10.1
	if validVulnerability(v) {
		t.Fatal("out-of-range CVSS accepted")
	}
}
