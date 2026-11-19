package authlete_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A server that make testauthlete promised (AUTHLETE_AS_URL set) and that
// can't serve discovery fails the run, so a misconfigured container reads
// as FAIL in make conformance rather than as a quiet SKIP.
func TestAuthleteReadiness(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Authlete /api/service/configuration API failed: HTTP 404 Not Found", http.StatusInternalServerError)
	}))
	defer broken.Close()
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{}`)) }))
	defer ok.Close()
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()

	tests := []struct {
		name     string
		url      string
		promised bool
		want     readiness
	}{
		{"healthy", ok.URL, true, ready},
		{"discovery 500, promised", broken.URL, true, notReadyFail},
		{"discovery 500, not promised", broken.URL, false, notReadySkip},
		{"unreachable, promised", down.URL, true, notReadyFail},
		{"unreachable, not promised", down.URL, false, notReadySkip},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := authleteReadiness(http.DefaultClient, tc.url, tc.promised)
			assert.Equal(t, tc.want, got, reason)
			if got != ready {
				assert.NotEmpty(t, reason)
			}
		})
	}
}
