package main

import "testing"

// One OIDF entry can name several plans that share a module, and a module
// that needs a person at the harness is expected-manual.
func TestEntryValidate_PlansAndManual(t *testing.T) {
	base := Entry{Suite: "oidf", Test: "oidcc-server-rotate-keys", Status: "expected-manual", Issue: 1, Owner: "o", Reason: "r", Expires: "2027-12-31"}
	tests := []struct {
		name    string
		mut     func(*Entry)
		wantErr bool
	}{
		{"plans list", func(e *Entry) { e.Plans = []string{"a", "b"} }, false},
		{"single plan", func(e *Entry) { e.Plan = "a" }, false},
		{"plan and plans", func(e *Entry) { e.Plan = "a"; e.Plans = []string{"b"} }, true},
		{"neither", func(*Entry) {}, true},
		{"manual on a native entry", func(e *Entry) { e.Test, e.ID = "", "TestX" }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.mut(&e)
			if err := e.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestEntryKey_Plans(t *testing.T) {
	e := Entry{Suite: "oidf", Plans: []string{"a", "b"}, Test: "m"}
	if got := e.Key(); got != "oidf::a,b::m" {
		t.Fatalf("Key() = %q", got)
	}
}
