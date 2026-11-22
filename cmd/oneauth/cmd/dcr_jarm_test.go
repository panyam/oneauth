package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bodyRecordingDCRAS answers registration and management requests and
// records each request body.
func bodyRecordingDCRAS(t *testing.T, bodies *[]map[string]any) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "token_endpoint": srv.URL + "/token", "registration_endpoint": srv.URL + "/apps/dcr"})
			return
		}
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		*bodies = append(*bodies, body)
		body["client_id"], body["registration_access_token"] = "c1", "tok"
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --authorization-signed-response-alg reaches the registration and the
// RFC 7592 update (JARM §3, issue 413).
func TestDCR_AuthorizationSignedResponseAlgFlag(t *testing.T) {
	var bodies []map[string]any
	as := bodyRecordingDCRAS(t, &bodies)
	df := &dcrFlags{format: "json"}

	var out bytes.Buffer
	require.NoError(t, runDCRRegister(context.Background(), &out, as.URL, df, &dcrRegisterFlags{clientName: "jarm", authorizationSignedResponseAlg: "ES256"}))
	require.NoError(t, runDCRPut(context.Background(), new(bytes.Buffer), as.URL, df, &dcrPutFlags{
		clientID: "c1", registrationAccessToken: "tok", registrationClientURI: as.URL + "/apps/dcr/c1", authorizationSignedResponseAlg: "PS256",
	}))
	require.Len(t, bodies, 2)
	assert.Equal(t, "ES256", bodies[0]["authorization_signed_response_alg"])
	assert.Equal(t, "PS256", bodies[1]["authorization_signed_response_alg"])
	assert.Contains(t, out.String(), `"authorization_signed_response_alg": "ES256"`, "the AS's record is printed back")

	for _, name := range []string{"register", "put"} {
		cmd := newDCRCommand()
		sub, _, err := cmd.Find([]string{name})
		require.NoError(t, err)
		assert.NotNil(t, sub.Flags().Lookup("authorization-signed-response-alg"), name)
	}
}
