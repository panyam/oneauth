package oidfconformance_test

// Phase-2 ratchet integration for the OIDF conformance discovery plan
// (issue 197). Runs the harness's `oidcc-config-certification-test-plan`
// against `cmd/oneauth-server`, parses per-check outcomes from the
// harness log, and diffs them against the external-suite entries in
// `../conformance/known-gaps.yaml`.
//
// The diff is local to this test (we don't import the conformance
// runner's diff library across submodule boundaries). The logic is
// simple enough — a small price for avoiding a cross-submodule tag
// release. If matrix-mode or multi-plan support lands, factor out.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/panyam/oneauth/tests/oidf-conformance/harness"
)

const (
	planName = "oidcc-config-certification-test-plan"
	testName = "oidcc-discovery-endpoint-verification"
)

// TestOIDF_OIDCC_ConfigCert_Discovery is the Phase-2 ratchet enforcement
// point: it runs the OIDF harness's discovery test and compares the
// per-check FAILURE / WARNING outcomes to the expected-fail entries in
// known-gaps.yaml.
//
// Verdicts (same model as the Go-native ratchet runner):
//
//   - observed FAILURE/WARNING with manifest entry → known gap, OK
//   - observed FAILURE/WARNING without manifest entry → REGRESSION (t.Errorf)
//   - manifest entry without observed FAILURE/WARNING → RATCHET-UP (t.Errorf)
//
// Skips gracefully when the harness or AS isn't running, so plain
// `go test ./...` invocations stay safe on dev machines without docker.
func TestOIDF_OIDCC_ConfigCert_Discovery(t *testing.T) {
	skipIfHarnessOrASNotReady(t)

	// 1. Drive the harness.
	client := harness.New(harnessURL())
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	planID, err := client.CreatePlan(ctx, planName, planConfig())
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	testID, err := client.RunTest(ctx, planID, testName, map[string]string{
		"server_metadata":     "discovery",
		"client_registration": "static_client",
	})
	if err != nil {
		t.Fatalf("run test: %v", err)
	}
	if _, err := client.WaitForCompletion(ctx, testID); err != nil {
		t.Fatalf("wait for completion: %v", err)
	}
	logEntries, err := client.GetLog(ctx, testID)
	if err != nil {
		t.Fatalf("get log: %v", err)
	}
	summary := harness.Summarize(logEntries)

	// 2. Load the manifest entries for this plan.
	expectedEntries := loadExpectedEntries(t, planName)
	expected := map[string]bool{}
	for k := range expectedEntries {
		expected[k] = true
	}

	// 3. Diff.
	observed := map[string]bool{}
	for _, f := range summary.Failures {
		observed[f.Src] = true
	}
	for _, w := range summary.Warnings {
		observed[w.Src] = true
	}

	// Regressions: observed but not expected.
	for _, src := range stableKeys(observed) {
		if !expected[src] {
			t.Errorf("REGRESSION: %q failed/warned but is not in known-gaps.yaml under suite=oidf, plan=%s. "+
				"If this is a known gap, add an entry; otherwise this is a real regression.", src, planName)
		}
	}
	// Ratchet-up: expected but not observed.
	for _, src := range stableKeys(expected) {
		if !observed[src] {
			t.Errorf("RATCHET-UP: %q is in known-gaps.yaml but did not fail/warn against the live harness. "+
				"Remove the entry to ratchet the gap up.", src)
		}
	}

	if t.Failed() {
		t.Logf("baseline check srcs from latest run: failures=%d warnings=%d",
			len(summary.Failures), len(summary.Warnings))
	}

	// 4. Regenerate SCORECARD.md from the latest harness output (runs
	// unconditionally — even on diff failure, the scorecard reflects
	// reality and the PR diff makes the drift visible).
	totals, rows := buildScorecard(logEntries, expectedEntries)
	if err := writeScorecard(findWorkspaceRoot(t), planName, testName, totals, rows); err != nil {
		t.Errorf("scorecard write failed: %v", err)
	}
}

// skipIfHarnessOrASNotReady skips when either dependency isn't reachable.
// Matches the testkcl/testauthlete skip pattern: dev machines without
// docker can still `go test ./...` without spurious failures.
//
// The AS liveness probe uses asProbeURL() (host-side reachable URL),
// not asURL() (Docker-side reachable URL) — host.docker.internal
// doesn't resolve from outside Docker. The probe trusts the same test
// CA the harness JVM trusts (issue 250).
func skipIfHarnessOrASNotReady(t *testing.T) {
	t.Helper()
	httpClient := &http.Client{Timeout: 3 * time.Second, Transport: harness.New("").HTTPClient.Transport}
	if _, err := httpClient.Get(harnessURL() + "/api/version"); err != nil {
		t.Skipf("OIDF harness not reachable at %s (run `make upoidf`): %v", harnessURL(), err)
	}
	probe := &http.Client{Timeout: 3 * time.Second, Transport: probeTransport(t)}
	if _, err := probe.Get(asProbeURL() + "/.well-known/openid-configuration"); err != nil {
		t.Skipf("oneauth-server not reachable at %s (run `make upoidf-as`): %v", asProbeURL(), err)
	}
}

// probeTransport returns an http.Transport that trusts the test CA
// under tests/oidf-conformance/certs/ca.crt — the same CA the harness
// JVM mounts. Falls back to the system trust store when the CA file is
// absent (lets a future plain-HTTP probe topology still work).
func probeTransport(t *testing.T) *http.Transport {
	t.Helper()
	caPath := filepath.Join("certs", "ca.crt")
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return &http.Transport{}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
}

// harnessURL returns the OIDF harness origin from env or the docker-
// compose default.
func harnessURL() string {
	if v := os.Getenv("OIDF_HARNESS_URL"); v != "" {
		return v
	}
	return "https://localhost.emobix.co.uk:8443"
}

// asURL returns the AS origin that the HARNESS uses to reach OneAuth.
// The harness lives in Docker; from inside the container, the host is
// `host.docker.internal` (Mac/Win Docker; Linux CI configures this via
// the docker compose extra_hosts entry in docker-compose-prebuilt.yml).
// Override with OIDF_AS_URL when running against a different topology.
//
// HTTPS by default (issue 250) — closes the 5 deployment-mode-noise
// expected-fails that the discovery plan flagged as
// `Expected https protocol for …`. The cert + truststore live under
// tests/oidf-conformance/certs/.
func asURL() string {
	if v := os.Getenv("OIDF_AS_URL"); v != "" {
		return v
	}
	return "https://host.docker.internal:8888"
}

// asProbeURL returns the AS origin that THE TEST PROCESS (running on
// the host, not in Docker) uses for liveness probing. host.docker.internal
// resolves only from inside containers, so we use plain localhost. The
// test process and the harness reach the AS via different routes;
// asURL() is for the harness, asProbeURL() for us.
//
// Override with OIDF_AS_PROBE_URL for non-default topologies (e.g.,
// the AS running on a remote host both the test and the harness reach
// through the same URL).
func asProbeURL() string {
	if v := os.Getenv("OIDF_AS_PROBE_URL"); v != "" {
		return v
	}
	return "https://localhost:8888"
}

// planConfig is the JSON config block POSTed to /api/plan. The harness
// uses `alias` only for display; `server.discoveryUrl` is the live
// pointer that drives the AS-side checks.
func planConfig() map[string]any {
	return map[string]any{
		"alias": "oneauth-phase2-discovery",
		"server": map[string]string{
			"discoveryUrl": asURL() + "/.well-known/openid-configuration",
		},
	}
}

// loadExpectedEntries parses tests/conformance/known-gaps.yaml and
// returns the full manifestEntry for each (suite=oidf, plan, status=
// expected-fail) tuple, keyed by `test` (check src). The scorecard
// uses the Issue + Reason fields; the diff logic uses only the keys.
func loadExpectedEntries(t *testing.T, plan string) map[string]manifestEntry {
	t.Helper()
	root := findWorkspaceRoot(t)
	path := filepath.Join(root, "tests", "conformance", "known-gaps.yaml")
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var entries []manifestEntry
	if err := yaml.Unmarshal(buf, &entries); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	out := map[string]manifestEntry{}
	for _, e := range entries {
		if e.Suite == "oidf" && e.Plan == plan && e.Status == "expected-fail" {
			out[e.Test] = e
		}
	}
	return out
}

// loadExpectedFails parses tests/conformance/known-gaps.yaml and returns
// the set of `test` (check src) values for the specified plan, suite=oidf,
// status=expected-fail. Path is resolved relative to the workspace root
// (the directory containing go.work) so the test runs from any cwd.
func loadExpectedFails(t *testing.T, plan string) map[string]bool {
	t.Helper()
	root := findWorkspaceRoot(t)
	path := filepath.Join(root, "tests", "conformance", "known-gaps.yaml")
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var entries []manifestEntry
	if err := yaml.Unmarshal(buf, &entries); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		if e.Suite == "oidf" && e.Plan == plan && e.Status == "expected-fail" {
			out[e.Test] = true
		}
	}
	return out
}

// manifestEntry mirrors the schema in tests/conformance/cmd/runner/manifest.go
// but is local to this package because the runner is a separate Go submodule.
// Issue + Reason are read for SCORECARD.md rendering.
type manifestEntry struct {
	Suite  string `yaml:"suite"`
	Plan   string `yaml:"plan,omitempty"`
	Test   string `yaml:"test,omitempty"`
	Status string `yaml:"status"`
	Issue  int    `yaml:"issue,omitempty"`
	Reason string `yaml:"reason,omitempty"`
}

// findWorkspaceRoot walks up from the test file's CWD to find go.work.
// Fatals the test if not found — the manifest path resolution assumes
// the standard workspace layout.
func findWorkspaceRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.work found walking up from %s", dir)
		}
		dir = parent
	}
}

// stableKeys returns map keys in sorted order so test failure messages
// are deterministic.
func stableKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Compile-time check that we link against fmt + encoding/json correctly
// — used in diagnostic helpers below if matrix-mode lands.
var _ = fmt.Sprintf
var _ = json.Marshal
var _ = strings.Contains
