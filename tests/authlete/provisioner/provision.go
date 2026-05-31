package provisioner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Options configures a single Provision/Deprovision run. Sensible
// defaults for the tests/authlete suite are applied by Defaults().
type Options struct {
	// SignAlg controls which signing algorithm Authlete will use for
	// access tokens. Authlete only emits JWTs (vs opaque tokens) when
	// both accessTokenSignAlg and jwks are set on the service.
	SignAlg string

	// RARTypes are the values added to the service's supported AD types
	// AND to the TestClient's per-client allowlist (Authlete enforces
	// both). Idempotent: types already present are not duplicated.
	RARTypes []string

	// TestClientAlias is the clientIdAlias of the OAuth client used by
	// the test suite (typically "TestClientId"). Provisioner extends
	// this client's authorizationDetailsTypes when adding RAR types —
	// Authlete rejects RAR requests for types the *client* hasn't
	// declared, even when the *service* allows them.
	TestClientAlias string

	// SnapshotPath is the file where the pre-provision state is persisted,
	// enabling Deprovision to restore it.
	SnapshotPath string
}

// Defaults returns Options with sensible values for the standard
// tests/authlete invocation. snapshotDir is typically
// tests/authlete/.frontend (gitignored).
//
// Note: introspection credentials are NOT provisioned — the java-oauth-
// server frontend ships with a hardcoded resource server `rs0`/`rs0-secret`
// in its bundled /resource_servers.json. The interop test uses those creds
// directly. If a future Authlete frontend deployment uses different RS
// credentials, set AUTHLETE_INTROSPECTOR_CLIENTID/SECRET in env to override.
func Defaults(snapshotDir string) Options {
	return Options{
		SignAlg:         "RS256",
		RARTypes:        []string{"payment_initiation"},
		TestClientAlias: "TestClientId",
		SnapshotPath:    filepath.Join(snapshotDir, ".preprovision.json"),
	}
}

// Snapshot captures the slice of pre-provision state we need to restore
// on deprovision. We do NOT snapshot the entire service blob (it's huge
// and most fields are operator-managed) — only the fields we mutate, so
// restore is a precise rollback rather than a wholesale overwrite that
// could wipe out concurrent operator changes.
type Snapshot struct {
	HadJWKS              bool     `json:"had_jwks"`
	JWKS                 string   `json:"jwks,omitempty"`
	PriorRARTypes        []string `json:"prior_rar_types"`
	HadRARTypes          bool     `json:"had_rar_types"`
	TestClientID         int64    `json:"test_client_id,omitempty"`
	PriorClientRARTypes  []string `json:"prior_client_rar_types"`
	HadClientRARTypes    bool     `json:"had_client_rar_types"`
}

// ProvisionReport summarizes what the provisioner did. Status is one of
// "provisioned" (mutations applied) or "already-provisioned" (idempotent
// no-op).
type ProvisionReport struct {
	Status              string
	JWKSGenerated       bool
	RARTypesAdded       []string
	ClientRARTypesAdded []string
}

// Provisioner orchestrates the idempotent service-configuration changes
// needed to flip the tests/authlete suite's SKIPs into PASSes.
type Provisioner struct {
	Client *Client
	Opts   Options
}

// Provision applies the configuration needed for the interop suite. It
// is idempotent: re-running on an already-provisioned service produces
// no further mutations and reports status "already-provisioned".
//
// Mutations applied in order:
//  1. Generate an RSA JWK Set + set the service's `jwks` + `accessTokenSignAlg`
//     fields, so Authlete signs JWTs instead of returning opaque tokens.
//  2. Add Opts.RARTypes to `supportedAuthorizationDetailsTypes`,
//     enabling the RAR round-trip test.
//  3. Register an introspector client (clientType=CONFIDENTIAL,
//     tokenAuthMethod=CLIENT_SECRET_BASIC) and write its credentials to
//     Opts.EnvFilePath for the test to consume.
//
// A snapshot of the pre-mutation state is written to Opts.SnapshotPath
// before any change so Deprovision can roll back.
func (p *Provisioner) Provision(ctx context.Context) (*ProvisionReport, error) {
	svc, err := p.Client.GetService(ctx)
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}

	report := &ProvisionReport{Status: "provisioned"}
	snapshot := Snapshot{}
	mutated := false

	// 1. JWKS — Authlete won't emit JWTs without one.
	if existing, _ := svc["jwks"].(string); existing == "" {
		kid := fmt.Sprintf("oneauth-test-%s-%d", p.Opts.SignAlg, time.Now().Unix())
		jwkSet, _, err := generateRSAJWKSet(kid, p.Opts.SignAlg)
		if err != nil {
			return nil, fmt.Errorf("generate JWKS: %w", err)
		}
		svc["jwks"] = jwkSet
		svc["accessTokenSignAlg"] = p.Opts.SignAlg
		report.JWKSGenerated = true
		mutated = true
	} else {
		snapshot.HadJWKS = true
		snapshot.JWKS = existing
	}

	// 2. RAR types — additive; only add what's missing.
	currentRARTypes := stringsField(svc, "supportedAuthorizationDetailsTypes")
	snapshot.PriorRARTypes = currentRARTypes
	snapshot.HadRARTypes = svc["supportedAuthorizationDetailsTypes"] != nil
	added := unionMissing(currentRARTypes, p.Opts.RARTypes)
	if len(added) > 0 {
		svc["supportedAuthorizationDetailsTypes"] = append(currentRARTypes, added...)
		report.RARTypesAdded = added
		mutated = true
	}

	if mutated {
		if _, err := p.Client.UpdateService(ctx, svc); err != nil {
			return nil, fmt.Errorf("update service: %w", err)
		}
	}

	// 3. TestClient RAR types — Authlete enforces declared-types on
	// the CLIENT in addition to the service. A token request that
	// includes authorization_details for a type the client hasn't
	// declared returns A249303 ("the client has not declared it may
	// use the type"), even when the service supports it.
	clientReport, err := p.updateTestClientRARTypes(ctx, &snapshot)
	if err != nil {
		return nil, fmt.Errorf("update test client RAR types: %w", err)
	}
	if len(clientReport) > 0 {
		report.ClientRARTypesAdded = clientReport
		mutated = true
	}

	if !mutated {
		report.Status = "already-provisioned"
	}

	// Persist snapshot so Deprovision has a rollback target.
	if err := writeSnapshot(p.Opts.SnapshotPath, &snapshot); err != nil {
		return nil, fmt.Errorf("write snapshot: %w", err)
	}

	return report, nil
}

// updateTestClientRARTypes finds the configured TestClient and extends
// its authorizationDetailsTypes with any RARTypes the client doesn't
// already declare. Returns the slice of added types (empty when no-op).
// Snapshots the client's prior state so Deprovision can restore.
func (p *Provisioner) updateTestClientRARTypes(ctx context.Context, snapshot *Snapshot) ([]string, error) {
	clients, err := p.Client.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	var testClient map[string]any
	for _, c := range clients {
		if stringField(c, "clientIdAlias") == p.Opts.TestClientAlias {
			testClient = c
			break
		}
	}
	if testClient == nil {
		return nil, fmt.Errorf("test client with alias %q not found in service", p.Opts.TestClientAlias)
	}
	clientID, _ := toInt64(testClient["clientId"])
	snapshot.TestClientID = clientID

	current := stringsField(testClient, "authorizationDetailsTypes")
	snapshot.PriorClientRARTypes = current
	snapshot.HadClientRARTypes = testClient["authorizationDetailsTypes"] != nil
	added := unionMissing(current, p.Opts.RARTypes)
	if len(added) == 0 {
		return nil, nil
	}
	testClient["authorizationDetailsTypes"] = append(current, added...)
	if _, err := p.Client.UpdateClient(ctx, clientID, testClient); err != nil {
		return nil, fmt.Errorf("update test client %d: %w", clientID, err)
	}
	return added, nil
}


// stringsField extracts a []string from a JSON-decoded map. Authlete
// returns array fields as []any (decoded from JSON arrays); we coerce
// per-element back to string, skipping non-strings (which shouldn't
// occur for these fields but defensive coding is cheap here).
func stringsField(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// toInt64 coerces a JSON-decoded numeric field to int64. encoding/json
// decodes JSON numbers as float64 by default; Authlete client IDs are
// integers but arrive as float64s when the response is JSON-decoded.
// Test fixtures may inject untyped int literals into map[string]any
// (Go's default integer type is int), so we accept those too.
func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// unionMissing returns the elements of want not already present in have.
// Preserves want's order; assumes neither slice has internal duplicates.
func unionMissing(have, want []string) []string {
	set := make(map[string]struct{}, len(have))
	for _, h := range have {
		set[h] = struct{}{}
	}
	var added []string
	for _, w := range want {
		if _, ok := set[w]; !ok {
			added = append(added, w)
		}
	}
	return added
}

func writeSnapshot(path string, snap *Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf, 0o600)
}

func readSnapshot(path string) (*Snapshot, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(buf, &snap); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	return &snap, nil
}

