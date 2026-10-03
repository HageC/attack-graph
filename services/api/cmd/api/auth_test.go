package main

import (
	"net/http/httptest"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	request := httptest.NewRequest("POST", "http://localhost:8080/api/v1/environments/northstar/assets", nil)
	request.Header.Set("Origin", "http://localhost:8080")
	if !sameOrigin(request) {
		t.Fatal("matching origin rejected")
	}
	request.Header.Set("Origin", "https://unrelated.example")
	if sameOrigin(request) {
		t.Fatal("cross-origin mutation accepted")
	}
}
func TestLoginLimiter(t *testing.T) {
	store := &AuthStore{attempts: map[string]loginAttempt{}}
	for i := 0; i < 10; i++ {
		if !store.allowAttempt("127.0.0.1:1200") {
			t.Fatalf("attempt %d rejected too early", i+1)
		}
	}
	if store.allowAttempt("127.0.0.1:1200") {
		t.Fatal("eleventh attempt accepted")
	}
}
