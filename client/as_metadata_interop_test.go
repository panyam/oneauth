package client_test

// Cross-package interop tests pinning the wire contract for AS metadata:
// the server-side type (apiauth.ASServerMetadata) emits the JSON document,
// and the client-side type (client.ASMetadata) decodes it. A unit test on
// either side alone can pass while the two have silently disagreed on a
// JSON tag — these tests exercise both halves through one httptest hop so
// a future rename on either side fails loudly.
//
// Lives under client_test (external) rather than client (internal) to
// avoid an import cycle and to follow the precedent set by
// jwt_bearer_grant_e2e_test.go / token_exchange_e2e_test.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestASMetadata_Interop_IssParamSupported exercises every leg of the RFC 9207
// advertisement tristate through both sides: server emits ASServerMetadata,
// httptest carries the JSON, client.DiscoverAS decodes into ASMetadata.
// A divergence in JSON tags between apiauth and client (rename on one side,
// forgotten on the other) would only surface here — unit tests on each
// package alone are blind to it.
//
// See: https://www.rfc-editor.org/rfc/rfc9207#section-3
func TestASMetadata_Interop_IssParamSupported(t *testing.T) {
	trueVal, falseVal := true, false
	cases := []struct {
		name     string
		serverIn *bool
		wantNil  bool
		wantVal  bool
	}{
		{"advertised_true", &trueVal, false, true},
		{"advertised_false", &falseVal, false, false},
		{"absent", nil, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			mux.Handle("/.well-known/openid-configuration", apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
				Issuer:                                     srv.URL,
				TokenEndpoint:                              srv.URL + "/oauth/token",
				AuthorizationResponseIssParameterSupported: tc.serverIn,
			}))

			got, err := client.DiscoverAS(srv.URL, client.WithHTTPClientForDiscovery(srv.Client()))
			require.NoError(t, err)

			if tc.wantNil {
				assert.Nil(t, got.AuthorizationResponseIssParameterSupported,
					"server omitted the field; client must decode it as nil so consumers can detect a legacy AS")
				return
			}
			require.NotNil(t, got.AuthorizationResponseIssParameterSupported,
				"server emitted the field; client must surface it as a non-nil pointer")
			assert.Equal(t, tc.wantVal, *got.AuthorizationResponseIssParameterSupported)
		})
	}
}
