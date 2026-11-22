package core

// Whether a request reached the server over HTTPS. A TLS-terminating proxy
// forwards plain HTTP and says the client's scheme in X-Forwarded-Proto or
// Forwarded. Anyone can send those headers, so they count only from a
// trusted proxy.
//
// See: https://www.rfc-editor.org/rfc/rfc7239#section-5.4
// See: https://cwe.mitre.org/data/definitions/348.html
// See: https://github.com/panyam/oneauth/issues/541

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustedProxiesIsHTTPS(t *testing.T) {
	proxies, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		remote    string
		tls       bool
		xfp       []string
		forwarded []string
		trusted   TrustedProxies
		want      bool
	}{
		"direct TLS":                        {remote: "203.0.113.5:4000", tls: true, want: true},
		"direct TLS, untrusted xfp http":    {remote: "203.0.113.5:4000", tls: true, xfp: []string{"http"}, want: true},
		"plain HTTP, no headers":            {remote: "203.0.113.5:4000", want: false},
		"trusted proxy says https":          {remote: "10.0.0.7:4000", xfp: []string{"https"}, trusted: proxies, want: true},
		"trusted proxy says HTTPS":          {remote: "10.0.0.7:4000", xfp: []string{"HTTPS"}, trusted: proxies, want: true},
		"trusted proxy says http":           {remote: "10.0.0.7:4000", xfp: []string{"http"}, trusted: proxies, want: false},
		"trusted proxy, no header":          {remote: "10.0.0.7:4000", trusted: proxies, want: false},
		"untrusted peer says https":         {remote: "203.0.113.5:4000", xfp: []string{"https"}, trusted: proxies, want: false},
		"no proxies configured":             {remote: "10.0.0.7:4000", xfp: []string{"https"}, want: false},
		"xfp list: only first counts":       {remote: "10.0.0.7:4000", xfp: []string{"http, https"}, trusted: proxies, want: false},
		"xfp list: first is https":          {remote: "10.0.0.7:4000", xfp: []string{" https ,http"}, trusted: proxies, want: true},
		"xfp repeated: first header counts": {remote: "10.0.0.7:4000", xfp: []string{"http", "https"}, trusted: proxies, want: false},
		"Forwarded proto=https":             {remote: "10.0.0.7:4000", forwarded: []string{"for=198.51.100.9;proto=https;by=10.0.0.7"}, trusted: proxies, want: true},
		"Forwarded quoted, mixed case":      {remote: "10.0.0.7:4000", forwarded: []string{`For="[2001:db8::1]"; Proto="HTTPS"`}, trusted: proxies, want: true},
		"Forwarded: first element counts":   {remote: "10.0.0.7:4000", forwarded: []string{"proto=http, proto=https"}, trusted: proxies, want: false},
		"Forwarded from untrusted peer":     {remote: "203.0.113.5:4000", forwarded: []string{"proto=https"}, trusted: proxies, want: false},
		"xfp wins over Forwarded":           {remote: "10.0.0.7:4000", xfp: []string{"http"}, forwarded: []string{"proto=https"}, trusted: proxies, want: false},
		"IPv4-mapped IPv6 trusted peer":     {remote: "[::ffff:10.0.0.7]:4000", xfp: []string{"https"}, trusted: proxies, want: true},
		"unparseable RemoteAddr":            {remote: "pipe", xfp: []string{"https"}, trusted: proxies, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://as.example/token", nil)
			r.RemoteAddr = tc.remote
			r.TLS = nil
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for _, v := range tc.xfp {
				r.Header.Add("X-Forwarded-Proto", v)
			}
			for _, v := range tc.forwarded {
				r.Header.Add("Forwarded", v)
			}
			assert.Equal(t, tc.want, tc.trusted.IsHTTPS(r))
		})
	}
}
