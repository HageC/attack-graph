package main

import "testing"

func TestLayoutBounds(t *testing.T) {
	if validLayoutName(" ") || validLayoutName("a") || !validLayoutName("Topology review") {
		t.Fatal("layout name validation failed")
	}
	if !validLayoutPosition(LayoutPosition{X: -100000, Y: 100000}) || validLayoutPosition(LayoutPosition{X: 100001}) {
		t.Fatal("layout position bounds failed")
	}
}
