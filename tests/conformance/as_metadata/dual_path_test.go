package as_metadata_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/panyam/oneauth/testutil"
)

// requiredFields are the AS metadata fields RFC 8414 §2 marks REQUIRED
// (issuer, token_endpoint) plus the RECOMMENDED jwks_uri, which OneAuth
// always populates and downstream clients need to validate signatures.
var requiredFields = []string{"issuer", "token_endpoint", "jwks_uri"}

// TestDualPathParity asserts that an OneAuth-built AS exposes its
// metadata at both well-known paths required by RFC 8414 §3.
//
// See:
//   - RFC 8414 §3 (https://www.rfc-editor.org/rfc/rfc8414#section-3)
//   - OIDC Discovery 1.0 §4
func TestDualPathParity(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	t.Run("oidc_path_required_fields", func(t *testing.T) {
		body := fetchJSON(t, srv.URL()+"/.well-known/openid-configuration")
		for _, f := range requiredFields {
			if _, ok := body[f]; !ok {
				t.Errorf("missing required AS metadata field %q at OIDC path", f)
			}
		}
	})

	t.Run("rfc8414_path_parity", func(t *testing.T) {
		oidcBody := fetchJSON(t, srv.URL()+"/.well-known/openid-configuration")
		rfc8414Body := fetchJSON(t, srv.URL()+"/.well-known/oauth-authorization-server")

		// Spec lets the two documents diverge on OIDC-specific fields
		// (e.g., id_token_signing_alg_values_supported), but every
		// field RFC 8414 itself defines must be identical between
		// them. Compare only the fields RFC 8414 mandates / commonly
		// includes; an OIDC-only field appearing on the OIDC path is
		// not a parity violation.
		for _, f := range requiredFields {
			if oidcBody[f] != rfc8414Body[f] {
				t.Errorf("field %q differs: oidc=%v rfc8414=%v",
					f, oidcBody[f], rfc8414Body[f])
			}
		}
	})
}

func fetchJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status=%d body=%s", url, resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return out
}
