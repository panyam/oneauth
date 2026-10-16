package core

// The client address used for rate limiting. X-Forwarded-For is set by
// whoever sends the request, so it is believed only when the direct peer is
// a proxy the deployment trusts. Otherwise rotating the header gives every
// guess a fresh rate-limit bucket.
//
// See: https://cwe.mitre.org/data/definitions/348.html
// See: https://cwe.mitre.org/data/definitions/307.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientIP(t *testing.T) {
	proxies, err := ParseTrustedProxies([]string{"10.0.0.0/8", "192.0.2.10"})
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		remote, xff, xRealIP string
		trusted              []string
		want                 string
	}{
		"no proxies: XFF ignored":           {remote: "203.0.113.5:4000", xff: "1.1.1.1", want: "203.0.113.5"},
		"no proxies: X-Real-IP ignored":     {remote: "203.0.113.5:4000", xRealIP: "1.1.1.1", want: "203.0.113.5"},
		"untrusted peer: XFF ignored":       {remote: "203.0.113.5:4000", xff: "1.1.1.1", trusted: []string{"10.0.0.0/8"}, want: "203.0.113.5"},
		"trusted peer: client from XFF":     {remote: "10.0.0.7:4000", xff: "198.51.100.9", trusted: []string{"10.0.0.0/8"}, want: "198.51.100.9"},
		"spoofed leftmost entry is skipped": {remote: "10.0.0.7:4000", xff: "1.1.1.1, 198.51.100.9", trusted: []string{"10.0.0.0/8"}, want: "198.51.100.9"},
		"chain of trusted proxies":          {remote: "10.0.0.7:4000", xff: "198.51.100.9, 192.0.2.10, 10.0.0.8", trusted: []string{"10.0.0.0/8", "192.0.2.10"}, want: "198.51.100.9"},
		"trusted peer, X-Real-IP fallback":  {remote: "10.0.0.7:4000", xRealIP: "198.51.100.9", trusted: []string{"10.0.0.0/8"}, want: "198.51.100.9"},
		"trusted peer, garbage XFF":         {remote: "10.0.0.7:4000", xff: "not-an-ip", trusted: []string{"10.0.0.0/8"}, want: "10.0.0.7"},
		"IPv6 peer":                         {remote: "[2001:db8::1]:4000", want: "2001:db8::1"},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xRealIP != "" {
				r.Header.Set("X-Real-IP", tc.xRealIP)
			}
			var tp TrustedProxies
			if tc.trusted != nil {
				tp, err = ParseTrustedProxies(tc.trusted)
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, ClientIP(r, tp))
		})
	}
	_ = proxies

	_, err = ParseTrustedProxies([]string{"not-a-cidr"})
	assert.Error(t, err)
}
