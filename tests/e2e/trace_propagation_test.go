package e2e_test

// In-process trace propagation: wire one TracerProvider across all four
// SEP-414-aware HTTP handlers (APIAuth /token, IntrospectionHandler,
// RevocationHandler, JWKSHandler), drive a request that fans through
// multiple endpoints, and assert every emitted span lands under the same
// inbound trace.
//
// This catches the integration mistake unit tests can't — a constructor
// that forgets to inherit TracerProvider (e.g. NewIntrospectionHandler
// failing to copy auth.TracerProvider) breaks cross-endpoint stitching
// while every per-handler unit test still passes.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/localauth"
	fsstore "github.com/panyam/oneauth/stores/fs"
)

const e2eTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
const e2eTraceID = "0af7651916cd43dd8448eb211c80319c"

func newE2ETracer(t *testing.T) (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return rec, tp
}

func findSpan(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// authServerWithTracing builds a minimal AS exposing /api/token,
// /oauth/introspect, /oauth/revoke, and /.well-known/jwks.json — all wired
// to a single TracerProvider. Returns the server, the issuer's APIAuth,
// the email + password of a pre-created test user, and the
// underlying KeyStore so callers can register additional apps if needed.
func authServerWithTracing(t *testing.T, tp trace.TracerProvider) (*httptest.Server, *apiauth.OneAuth, string, string, keys.KeyStorage) {
	t.Helper()

	tmpDir := t.TempDir()
	userStore := fsstore.NewFSUserStore(tmpDir)
	identityStore := fsstore.NewFSIdentityStore(tmpDir)
	channelStore := fsstore.NewFSChannelStore(tmpDir)
	refreshStore := fsstore.NewFSRefreshTokenStore(tmpDir)

	email := "trace-e2e@example.com"
	password := "password123"
	createUser := localauth.NewCreateUserFunc(userStore, identityStore, channelStore)
	_, err := createUser(&localauth.Credentials{Username: "traceuser", Email: &email, Password: password})
	require.NoError(t, err)

	keyStore := keys.NewInMemoryKeyStore()

	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:            keyStore,
		SigningKey:          []byte("trace-e2e-secret-32-chars-long!!"),
		SigningAlg:          "HS256",
		Issuer:              "oneauth-trace-e2e",
		RefreshStore:        refreshStore,
		ValidateCredentials: localauth.NewCredentialsValidator(identityStore, channelStore, userStore),
		GetSubjectScopes: func(string) ([]string, error) {
			return []string{core.ScopeRead, core.ScopeWrite}, nil
		},
		TracerProvider: tp,
	})
	tokenEndpoint := apiauth.NewTokenEndpointHandler(oa)
	tokenEndpoint.TracerProvider = tp

	introspectionHandler := oa.IntrospectionHTTPHandler()
	introspectionHandler.TracerProvider = tp
	revocationHandler := oa.RevocationHTTPHandler()
	revocationHandler.TracerProvider = tp

	mux := http.NewServeMux()
	mux.Handle("POST /api/token", tokenEndpoint)
	mux.Handle("POST /oauth/introspect", introspectionHandler)
	mux.Handle("POST /oauth/revoke", revocationHandler)
	mux.Handle("GET /.well-known/jwks.json", &keys.JWKSHandler{KeyStore: keyStore, TracerProvider: tp})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, oa, email, password, keyStore
}

func TestE2E_TraceparentPropagates_AcrossTokenIntrospectRevokeJWKS(t *testing.T) {
	rec, tp := newE2ETracer(t)
	srv, _, email, password, keyStore := authServerWithTracing(t, tp)

	// Register a client so /oauth/introspect and /oauth/revoke can
	// successfully authenticate via client_secret_basic — without that
	// they short-circuit at 401 before dispatching through the
	// introspector / revoker that emit downstream spans.
	const introspectClientID, introspectClientSecret = "rs-1", "rs-secret"
	_, err := keyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  introspectClientID,
		Key:       []byte(introspectClientSecret),
		Algorithm: "HS256",
	}})
	require.NoError(t, err)

	// 1. POST /api/token with an inbound traceparent — mint an access token.
	body, _ := json.Marshal(map[string]string{
		"grant_type": "password",
		"username":   email,
		"password":   password,
	})
	tokenReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/token", strings.NewReader(string(body)))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenReq.Header.Set("traceparent", e2eTraceparent)
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenBody struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenBody))
	tokenResp.Body.Close()
	require.NotEmpty(t, tokenBody.AccessToken)

	// 2. POST /oauth/introspect — authenticated, must reach the introspector
	//    so it dispatches through signature_verify.
	form := url.Values{"token": {tokenBody.AccessToken}}
	introReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/introspect", strings.NewReader(form.Encode()))
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.Header.Set("traceparent", e2eTraceparent)
	introReq.SetBasicAuth(introspectClientID, introspectClientSecret)
	introResp, err := http.DefaultClient.Do(introReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, introResp.StatusCode, "introspect must succeed so signature_verify runs")
	introResp.Body.Close()

	// 3. POST /oauth/revoke — authenticated; always returns 200 per RFC 7009 §2.2.
	revokeReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/revoke", strings.NewReader(form.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeReq.Header.Set("traceparent", e2eTraceparent)
	revokeReq.SetBasicAuth(introspectClientID, introspectClientSecret)
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	require.NoError(t, err)
	revokeResp.Body.Close()

	// 4. GET /.well-known/jwks.json with the SAME inbound traceparent.
	jwksReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/.well-known/jwks.json", nil)
	jwksReq.Header.Set("traceparent", e2eTraceparent)
	jwksResp, err := http.DefaultClient.Do(jwksReq)
	require.NoError(t, err)
	jwksResp.Body.Close()

	// All four handlers must have emitted a span carrying the inbound trace ID.
	wantNames := []string{
		"oneauth.token.issue",
		"oneauth.introspect",
		"oneauth.revoke",
		"oneauth.jwks.serve",
	}
	spans := rec.Ended()
	for _, name := range wantNames {
		s := findSpan(spans, name)
		require.NotNil(t, s, "expected span %q to be emitted (sign that the handler forgot to inherit TracerProvider)", name)
		assert.Equal(t, e2eTraceID, s.SpanContext().TraceID().String(),
			"span %q should be parented under the inbound traceparent", name)
		assert.True(t, s.Parent().IsRemote(),
			"span %q parent should be the remote inbound caller", name)
	}

	// /token also triggers oneauth.signature_verify when the lazy validator
	// is exercised. The introspect handler delegates to it via APIAuth.Validator,
	// so signature_verify must also be present and stitched.
	sv := findSpan(spans, "oneauth.signature_verify")
	require.NotNil(t, sv, "introspect must dispatch through signature_verify")
	assert.Equal(t, e2eTraceID, sv.SpanContext().TraceID().String(),
		"signature_verify must inherit the inbound trace via its caller's ctx")
}
