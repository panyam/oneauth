package keys

// The JWKS response, issue 88's "Key Management" walk: a 304 carries the
// same ETag and Cache-Control a 200 would (RFC 9110 §15.4.5), so a cache
// revalidating keeps the right lifetime.
//
// See: https://www.rfc-editor.org/rfc/rfc9110#section-15.4.5

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/utils"
)

func jwksFixture(t *testing.T) *JWKSHandler {
	t.Helper()
	ks := NewInMemoryKeyStore()
	_, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	ks.PutKey(context.Background(), &PutKeyRequest{Record: &KeyRecord{ClientID: "app", Key: pubPEM, Algorithm: "RS256"}})
	return &JWKSHandler{KeyStore: ks}
}

func TestJWKSHeaders_NotModifiedKeepsCacheHeaders(t *testing.T) {
	h := jwksFixture(t)
	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on 200")
	}

	for _, inm := range []string{etag, `"other", ` + etag, "W/" + etag} {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		req.Header.Set("If-None-Match", inm)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotModified {
			t.Errorf("If-None-Match %s: got %d, want 304", inm, rr.Code)
			continue
		}
		if rr.Header().Get("ETag") != etag || rr.Header().Get("Cache-Control") != first.Header().Get("Cache-Control") {
			t.Errorf("304 for %s: ETag %q Cache-Control %q, want the 200's", inm, rr.Header().Get("ETag"), rr.Header().Get("Cache-Control"))
		}
	}
}
