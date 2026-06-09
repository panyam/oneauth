package cmd

// Tests for `oneauth dcr <register|get|put|delete>` against an in-memory
// AS that serves RFC 8414 metadata + the RFC 7591 registration endpoint
// + the RFC 7592 management endpoint.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type syntheticDCRAS struct {
	srv *httptest.Server
	mu  sync.Mutex
	// clients keyed by client_id. Holds registration metadata + a
	// rotating registration_access_token (RFC 7592 §2.2 rotates on PUT).
	clients map[string]*dcrClientState
}

type dcrClientState struct {
	clientName   string
	clientURI    string
	redirectURIs []string
	grantTypes   []string
	accessToken  string
}

func newSyntheticDCRAS(t *testing.T) *syntheticDCRAS {
	t.Helper()
	as := &syntheticDCRAS{clients: map[string]*dcrClientState{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                as.srv.URL,
			"token_endpoint":        as.srv.URL + "/token",
			"registration_endpoint": as.srv.URL + "/apps/dcr",
		})
	})
	mux.HandleFunc("/apps/dcr", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		clientID := fmt.Sprintf("client-%d", len(as.clients)+1)
		token := fmt.Sprintf("regtok-%s", clientID)
		state := &dcrClientState{
			clientName:  asString(body["client_name"]),
			clientURI:   asString(body["client_uri"]),
			accessToken: token,
		}
		if v, ok := body["redirect_uris"].([]any); ok {
			for _, u := range v {
				state.redirectURIs = append(state.redirectURIs, asString(u))
			}
		}
		if v, ok := body["grant_types"].([]any); ok {
			for _, g := range v {
				state.grantTypes = append(state.grantTypes, asString(g))
			}
		}
		as.mu.Lock()
		as.clients[clientID] = state
		as.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                 clientID,
			"client_secret":             "secret-" + clientID,
			"client_name":               state.clientName,
			"redirect_uris":             state.redirectURIs,
			"grant_types":               state.grantTypes,
			"registration_access_token": token,
			"registration_client_uri":   as.srv.URL + "/apps/dcr/" + clientID,
		})
	})
	mux.HandleFunc("/apps/dcr/", func(w http.ResponseWriter, r *http.Request) {
		clientID := strings.TrimPrefix(r.URL.Path, "/apps/dcr/")
		as.mu.Lock()
		state, ok := as.clients[clientID]
		as.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+state.accessToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_token"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id":                 clientID,
				"client_name":               state.clientName,
				"redirect_uris":             state.redirectURIs,
				"grant_types":               state.grantTypes,
				"registration_access_token": state.accessToken,
				"registration_client_uri":   as.srv.URL + "/apps/dcr/" + clientID,
			})
		case http.MethodPut:
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			as.mu.Lock()
			state.clientName = asString(body["client_name"])
			state.redirectURIs = nil
			if v, ok := body["redirect_uris"].([]any); ok {
				for _, u := range v {
					state.redirectURIs = append(state.redirectURIs, asString(u))
				}
			}
			// RFC 7592 §2.2 rotates the token on every successful PUT.
			state.accessToken = state.accessToken + "-rotated"
			as.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id":                 clientID,
				"client_name":               state.clientName,
				"redirect_uris":             state.redirectURIs,
				"registration_access_token": state.accessToken,
				"registration_client_uri":   as.srv.URL + "/apps/dcr/" + clientID,
			})
		case http.MethodDelete:
			as.mu.Lock()
			delete(as.clients, clientID)
			as.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestRunDCRRegister_HappyPath(t *testing.T) {
	as := newSyntheticDCRAS(t)
	df := &dcrFlags{format: "json"}
	rf := &dcrRegisterFlags{
		clientName:   "demo",
		redirectURIs: []string{"https://app.example/cb"},
		grantTypes:   []string{"authorization_code", "refresh_token"},
	}
	var stdout bytes.Buffer
	require.NoError(t, runDCRRegister(context.Background(), &stdout, as.srv.URL, df, rf))

	var out map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, "client-1", out["client_id"])
	assert.Equal(t, "regtok-client-1", out["registration_access_token"])
}

func TestRunDCRRegister_BashFormatExportsCredentials(t *testing.T) {
	as := newSyntheticDCRAS(t)
	df := &dcrFlags{format: "bash"}
	rf := &dcrRegisterFlags{clientName: "demo"}
	var stdout bytes.Buffer
	require.NoError(t, runDCRRegister(context.Background(), &stdout, as.srv.URL, df, rf))
	out := stdout.String()
	assert.Contains(t, out, "export OAUTH_CLIENT_ID='client-1'")
	assert.Contains(t, out, "export OAUTH_REGISTRATION_ACCESS_TOKEN='regtok-client-1'")
}

func TestRunDCRGet_HappyPath(t *testing.T) {
	as := newSyntheticDCRAS(t)
	// Register first.
	df := &dcrFlags{format: "json"}
	require.NoError(t, runDCRRegister(context.Background(), new(bytes.Buffer), as.srv.URL,
		df, &dcrRegisterFlags{clientName: "demo"}))

	gf := &dcrGetFlags{
		clientID:                "client-1",
		registrationAccessToken: "regtok-client-1",
	}
	var stdout bytes.Buffer
	require.NoError(t, runDCRGet(context.Background(), &stdout, as.srv.URL, df, gf))

	var out map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, "client-1", out["client_id"])
	assert.Equal(t, "demo", out["client_name"])
}

func TestRunDCRGet_WrongTokenRejected(t *testing.T) {
	as := newSyntheticDCRAS(t)
	require.NoError(t, runDCRRegister(context.Background(), new(bytes.Buffer), as.srv.URL,
		&dcrFlags{format: "json"}, &dcrRegisterFlags{clientName: "demo"}))

	gf := &dcrGetFlags{
		clientID:                "client-1",
		registrationAccessToken: "WRONG",
	}
	err := runDCRGet(context.Background(), new(bytes.Buffer), as.srv.URL, &dcrFlags{format: "json"}, gf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestRunDCRPut_UpdatesAndRotatesToken(t *testing.T) {
	as := newSyntheticDCRAS(t)
	df := &dcrFlags{format: "json"}
	require.NoError(t, runDCRRegister(context.Background(), new(bytes.Buffer), as.srv.URL,
		df, &dcrRegisterFlags{clientName: "demo"}))

	pf := &dcrPutFlags{
		clientID:                "client-1",
		registrationAccessToken: "regtok-client-1",
		clientName:              "demo-renamed",
		redirectURIs:            []string{"https://app.example/v2/cb"},
	}
	var stdout bytes.Buffer
	require.NoError(t, runDCRPut(context.Background(), &stdout, as.srv.URL, df, pf))

	var out map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, "demo-renamed", out["client_name"])
	assert.Equal(t, "regtok-client-1-rotated", out["registration_access_token"],
		"PUT MUST surface the rotated registration_access_token (RFC 7592 §2.2)")
}

func TestRunDCRDelete_HappyPath(t *testing.T) {
	as := newSyntheticDCRAS(t)
	df := &dcrFlags{format: "json"}
	require.NoError(t, runDCRRegister(context.Background(), new(bytes.Buffer), as.srv.URL,
		df, &dcrRegisterFlags{clientName: "demo"}))

	xf := &dcrDeleteFlags{
		clientID:                "client-1",
		registrationAccessToken: "regtok-client-1",
	}
	var stdout bytes.Buffer
	require.NoError(t, runDCRDelete(context.Background(), &stdout, as.srv.URL, df, xf))

	var out map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	assert.Equal(t, true, out["deleted"])

	// And the client is gone — subsequent get yields unauthorized (RFC 7592
	// returns 401 for unknown client_id to avoid existence probing).
	gf := &dcrGetFlags{
		clientID:                "client-1",
		registrationAccessToken: "regtok-client-1",
	}
	require.Error(t, runDCRGet(context.Background(), new(bytes.Buffer), as.srv.URL, df, gf))
}

func TestRunDCRGet_NeitherIDNorURI(t *testing.T) {
	as := newSyntheticDCRAS(t)
	df := &dcrFlags{format: "json"}
	err := runDCRGet(context.Background(), new(bytes.Buffer), as.srv.URL, df, &dcrGetFlags{
		registrationAccessToken: "regtok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client-id")
}
