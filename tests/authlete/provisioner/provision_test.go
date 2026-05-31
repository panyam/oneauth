package provisioner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAuthlete is an in-memory mock of the Authlete V3 management API.
// It tracks the service state across requests so tests can verify the
// provisioner's idempotency and snapshot/restore semantics without
// touching the real Authlete cloud.
type fakeAuthlete struct {
	serviceID string
	service   map[string]any
	clients   []map[string]any
	nextID    atomic.Int64
	calls     atomic.Int64
}

func newFakeAuthlete(serviceID string) *fakeAuthlete {
	f := &fakeAuthlete{
		serviceID: serviceID,
		service: map[string]any{
			"apiKey":             3547200388,
			"serviceName":        "TestService",
			"accessTokenSignAlg": "RS256",
			// jwks deliberately absent — provision should add it
			// supportedAuthorizationDetailsTypes deliberately absent
		},
		// Pre-existing TestClient — Authlete services come with at
		// least one OAuth client registered. Provision must extend
		// this client's authorizationDetailsTypes when adding RAR
		// types to the service.
		clients: []map[string]any{
			{
				"clientId":       1506059443,
				"clientIdAlias":  "TestClientId",
				"clientType":     "CONFIDENTIAL",
			},
		},
	}
	f.nextID.Store(2000000000)
	return f
}

func (f *fakeAuthlete) handler() http.Handler {
	mux := http.NewServeMux()
	base := "/api/" + f.serviceID
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Surface unrouted requests with a useful diagnostic so test failures
		// don't masquerade as Authlete-side errors.
		http.Error(w, "fakeAuthlete: no handler for "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	})

	mux.HandleFunc(base+"/service/get", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		_ = json.NewEncoder(w).Encode(f.service)
	})

	mux.HandleFunc(base+"/service/update", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var svc map[string]any
		_ = json.Unmarshal(body, &svc)
		f.service = svc
		_ = json.NewEncoder(w).Encode(svc)
	})

	mux.HandleFunc(base+"/client/get/list", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"totalCount": len(f.clients),
			"clients":    f.clients,
		})
	})

	mux.HandleFunc(base+"/client/create", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var client map[string]any
		_ = json.Unmarshal(body, &client)
		client["clientId"] = f.nextID.Add(1)
		client["clientSecret"] = "fake-secret-" + client["clientName"].(string)
		f.clients = append(f.clients, client)
		_ = json.NewEncoder(w).Encode(client)
	})

	mux.HandleFunc(base+"/client/update/", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		id := strings.TrimPrefix(r.URL.Path, base+"/client/update/")
		body, _ := io.ReadAll(r.Body)
		var updated map[string]any
		_ = json.Unmarshal(body, &updated)
		for i, c := range f.clients {
			cid, _ := toInt64(c["clientId"])
			if cidStr(cid) == id {
				f.clients[i] = updated
				_ = json.NewEncoder(w).Encode(updated)
				return
			}
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc(base+"/client/delete/", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		// path-prefix match; extract trailing ID
		id := strings.TrimPrefix(r.URL.Path, base+"/client/delete/")
		filtered := f.clients[:0]
		for _, c := range f.clients {
			cid, _ := toInt64(c["clientId"])
			if cidStr(cid) != id {
				filtered = append(filtered, c)
			}
		}
		f.clients = filtered
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}

func cidStr(id int64) string {
	// strconv.FormatInt without an import — tiny inline.
	if id == 0 {
		return "0"
	}
	var b []byte
	neg := id < 0
	if neg {
		id = -id
	}
	for id > 0 {
		b = append([]byte{byte('0' + id%10)}, b...)
		id /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func newTestProvisioner(t *testing.T) (*Provisioner, *fakeAuthlete) {
	t.Helper()
	fake := newFakeAuthlete("3547200388")
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)

	tmp := t.TempDir()
	return &Provisioner{
		Client: &Client{
			BaseURL:     srv.URL,
			ServiceID:   "3547200388",
			AccessToken: "fake-token",
			HTTPClient:  srv.Client(),
		},
		Opts: Options{
			SignAlg:         "RS256",
			RARTypes:        []string{"payment_initiation"},
			TestClientAlias: "TestClientId",
			SnapshotPath:    filepath.Join(tmp, ".preprovision.json"),
		},
	}, fake
}

// TestProvision_FreshService verifies that a vanilla Authlete service
// (no JWKS, no RAR types) gets both the service-level + client-level
// mutations applied in one Provision call.
func TestProvision_FreshService(t *testing.T) {
	p, fake := newTestProvisioner(t)

	report, err := p.Provision(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "provisioned", report.Status)
	assert.True(t, report.JWKSGenerated)
	assert.Equal(t, []string{"payment_initiation"}, report.RARTypesAdded)
	assert.Equal(t, []string{"payment_initiation"}, report.ClientRARTypesAdded)

	// Service-level mutations landed
	assert.NotEmpty(t, fake.service["jwks"], "service should have JWKS after provision")
	assert.Equal(t, "RS256", fake.service["accessTokenSignAlg"])
	rarTypes := stringsField(fake.service, "supportedAuthorizationDetailsTypes")
	assert.Contains(t, rarTypes, "payment_initiation")

	// Client-level mutation landed — the pre-existing TestClient now declares the RAR type
	require.Len(t, fake.clients, 1)
	clientRARTypes := stringsField(fake.clients[0], "authorizationDetailsTypes")
	assert.Contains(t, clientRARTypes, "payment_initiation",
		"TestClient must have payment_initiation declared (Authlete A249303 otherwise)")

	// Snapshot persisted
	_, err = readSnapshot(p.Opts.SnapshotPath)
	assert.NoError(t, err, "snapshot file should be readable post-provision")
}

// TestProvision_Idempotent verifies the recommended invariant: running
// provision twice on the same service produces no additional mutations
// on the second run, and reports "already-provisioned".
func TestProvision_Idempotent(t *testing.T) {
	p, fake := newTestProvisioner(t)

	_, err := p.Provision(context.Background())
	require.NoError(t, err)
	clientsAfterFirst := len(fake.clients)
	jwksAfterFirst := fake.service["jwks"]

	report, err := p.Provision(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "already-provisioned", report.Status,
		"second provision must detect existing state and report no-op")
	assert.Len(t, fake.clients, clientsAfterFirst, "no new clients on second provision")
	assert.Equal(t, jwksAfterFirst, fake.service["jwks"], "JWKS not regenerated on second provision")
}

// TestDeprovision_RestoresSnapshot verifies the inverse path: after
// provision mutates the service + TestClient, deprovision returns
// both to the pre-provision state (JWKS gone, service RAR types gone,
// client RAR types gone). The TestClient itself is NOT deleted — it
// was pre-existing and provision only added to its RAR types list.
func TestDeprovision_RestoresSnapshot(t *testing.T) {
	p, fake := newTestProvisioner(t)

	_, err := p.Provision(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, fake.service["jwks"])
	require.Len(t, fake.clients, 1)

	err = p.Deprovision(context.Background())
	require.NoError(t, err)

	_, hasJWKS := fake.service["jwks"]
	assert.False(t, hasJWKS, "JWKS should be removed by deprovision")
	_, hasRAR := fake.service["supportedAuthorizationDetailsTypes"]
	assert.False(t, hasRAR, "service RAR types field should be removed")
	require.Len(t, fake.clients, 1, "TestClient stays (we only added to its RAR types, not created it)")
	_, hasClientRAR := fake.clients[0]["authorizationDetailsTypes"]
	assert.False(t, hasClientRAR, "TestClient's authorizationDetailsTypes field should be removed")
}

// TestDeprovision_PreservesOperatorRARTypes verifies that when the
// operator had pre-existing RAR types, deprovision restores them (not
// removes the field entirely). Catches the bug where we'd otherwise
// nuke operator config we never touched.
func TestDeprovision_PreservesOperatorRARTypes(t *testing.T) {
	p, fake := newTestProvisioner(t)
	// Pre-existing operator config: a different RAR type already registered.
	fake.service["supportedAuthorizationDetailsTypes"] = []any{"operator_only_type"}

	_, err := p.Provision(context.Background())
	require.NoError(t, err)
	rarAfter := stringsField(fake.service, "supportedAuthorizationDetailsTypes")
	assert.ElementsMatch(t, []string{"operator_only_type", "payment_initiation"}, rarAfter,
		"provision should add our type alongside operator's, not replace")

	err = p.Deprovision(context.Background())
	require.NoError(t, err)
	rarFinal := stringsField(fake.service, "supportedAuthorizationDetailsTypes")
	assert.ElementsMatch(t, []string{"operator_only_type"}, rarFinal,
		"deprovision should leave operator's type intact, remove only ours")
}

// TestDeprovision_PreservesOperatorJWKS verifies the operator-JWKS
// counterpart: when the service already had a JWKS (operator-managed),
// provision must NOT regenerate, and deprovision must NOT remove it.
func TestDeprovision_PreservesOperatorJWKS(t *testing.T) {
	p, fake := newTestProvisioner(t)
	operatorJWKS := `{"keys":[{"kid":"operator-key","kty":"RSA"}]}`
	fake.service["jwks"] = operatorJWKS

	report, err := p.Provision(context.Background())
	require.NoError(t, err)
	assert.False(t, report.JWKSGenerated, "provision should not regenerate when operator JWKS present")
	assert.Equal(t, operatorJWKS, fake.service["jwks"], "operator JWKS preserved through provision")

	err = p.Deprovision(context.Background())
	require.NoError(t, err)
	assert.Equal(t, operatorJWKS, fake.service["jwks"], "operator JWKS preserved through deprovision")
}

// TestDeprovision_MissingSnapshot returns ErrSnapshotNotFound so the
// CLI can distinguish "nothing to roll back" from genuine API failures.
func TestDeprovision_MissingSnapshot(t *testing.T) {
	p, _ := newTestProvisioner(t)
	err := p.Deprovision(context.Background())
	assert.ErrorIs(t, err, ErrSnapshotNotFound,
		"absent snapshot should surface as ErrSnapshotNotFound")
}
