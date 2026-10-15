package apiauth_test

// htu comparison (RFC 9449 §4.3 item 9). The RFC has the server compare the
// URIs after syntax-based and scheme-based normalization (RFC 3986 §6.2.2
// and §6.2.3), so two spellings of the same URI must match and two different
// URIs must not.
//
// References:
//   - RFC 9449 §4.3 (https://www.rfc-editor.org/rfc/rfc9449#section-4.3)
//   - RFC 9449 §11.8 (https://www.rfc-editor.org/rfc/rfc9449#section-11.8)
//   - RFC 3986 §6.2 (https://www.rfc-editor.org/rfc/rfc3986#section-6.2)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panyam/oneauth/apiauth"
)

func TestDPoPProof_HTUNormalization(t *testing.T) {
	_, sign := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})
	cases := []struct {
		name      string
		htu, want string
		match     bool
	}{
		{"default https port", "https://as.example.com:443/api/token", "https://as.example.com/api/token", true},
		{"default http port", "http://as.example.com:80/api/token", "http://as.example.com/api/token", true},
		{"empty path is /", "https://as.example.com", "https://as.example.com/", true},
		{"percent-encoding case", "https://as.example.com/a%2fb", "https://as.example.com/a%2Fb", true},
		{"encoded unreserved character", "https://as.example.com/%7Euser", "https://as.example.com/~user", true},
		{"dot segments", "https://as.example.com/a/./b/../c", "https://as.example.com/a/c", true},
		{"path case differs", "https://as.example.com/Token", "https://as.example.com/token", false},
		{"non-default port", "https://as.example.com:8443/api/token", "https://as.example.com/api/token", false},
		{"encoded slash is not a slash", "https://as.example.com/a%2Fb", "https://as.example.com/a/b", false},
		{"scheme differs", "http://as.example.com/api/token", "https://as.example.com/api/token", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), &apiauth.DPoPProofRequest{
				Proof:  sign(proofOpts{url: c.htu}),
				Method: testProofMethod,
				URL:    c.want,
			})
			if c.match {
				assert.NoError(t, err)
			} else {
				assertInvalidProof(t, err)
			}
		})
	}
}

// The expected htu is built from the request's escaped path, so a resource
// whose path carries an encoded slash is checked as the client named it.
func TestDPoPProof_ResourceHTUKeepsEncodedPath(t *testing.T) {
	_, sign := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: "https://rs.example.com"})
	token := "access-token"

	req := httptest.NewRequest(http.MethodGet, "/files/a%2Fb", nil)
	req.Header.Set("DPoP", sign(proofOpts{method: http.MethodGet, url: "https://rs.example.com/files/a%2Fb", ath: athFor(token)}))
	_, err := v.ConfirmResource(context.Background(), req, token)

	assert.NoError(t, err)
}
