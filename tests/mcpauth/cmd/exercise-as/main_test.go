package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeChecks(t *testing.T, dir, id string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `[{"id":"` + id + `","name":"` + id + `","status":"SUCCESS"}]`
	if err := os.WriteFile(filepath.Join(dir, "checks.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadScenario_PicksTheScenarioNotOneWhoseNameExtendsIt(t *testing.T) {
	out := t.TempDir()
	writeChecks(t, filepath.Join(out, "authorization-server-dpop-2026-11-21T09-38-38-216Z"), "dpop-check")
	writeChecks(t, filepath.Join(out, "authorization-server-dpop-extra-2026-11-21T09-38-39-000Z"), "other")
	checks, err := readScenario(out, "dpop")
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].ID != "dpop-check" {
		t.Fatalf("checks = %+v", checks)
	}
}

func TestReadScenario_MissingIsAnError(t *testing.T) {
	if _, err := readScenario(t.TempDir(), "authorization-code-grant"); err == nil {
		t.Fatal("a scenario with no checks.json must be an error, so the run can't pass without it")
	}
}
