package provision

import "testing"

func TestProvisionInputValidation(t *testing.T) {
	for _, email := range []string{"plain-address", "Name <a@example.com>", "a@example.com, b@example.com"} {
		if _, err := NormalizeEmail(email); err == nil {
			t.Fatalf("accepted invalid email %q", email)
		}
	}
	email, err := NormalizeEmail("  ADMIN@Example.com ")
	if err != nil || email != "admin@example.com" {
		t.Fatalf("unexpected normalized email %q: %v", email, err)
	}
	if ValidatePassword("short") == nil || ValidatePassword("long-enough-password") != nil {
		t.Fatal("password bounds failed")
	}
	if ValidateRole("owner") == nil || ValidateRole("editor") != nil {
		t.Fatal("role bounds failed")
	}
}
