package apiauth_test

// Behind a TLS-terminating proxy the AS receives plain HTTP while the
// client called https. A URL derived from the request then has the wrong
// scheme: every DPoP proof fails its htu check (RFC 9449 §4.3) and every
// client assertion fails its aud check. A trusted proxy's
// X-Forwarded-Proto fixes the scheme. From any other peer the header is
// ignored, and a configured URL always wins.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3
// See: https://cwe.mitre.org/data/definitions/348.html
// See: https://github.com/panyam/oneauth/issues/541

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

// httptest.NewRequest sets RemoteAddr to 192.0.2.1:1234.
func proxies(t *testing.T, cidrs ...string) core.TrustedProxies {
	t.Helper()
	tp, err := core.ParseTrustedProxies(cidrs)
	require.NoError(t, err)
	return tp
}

func TestDPoPHTU_SchemeFromTrustedProxy(t *testing.T) {
	_, sign := newProofSigner(t)
	for name, tc := range map[string]struct {
		cfg    apiauth.DPoPConfig
		xfp    string
		wantOK bool
	}{
		"trusted proxy says https":        {cfg: apiauth.DPoPConfig{TrustedProxies: proxies(t, "192.0.2.0/24")}, xfp: "https", wantOK: true},
		"trusted proxy says http":         {cfg: apiauth.DPoPConfig{TrustedProxies: proxies(t, "192.0.2.0/24")}, xfp: "http"},
		"untrusted peer says https":       {cfg: apiauth.DPoPConfig{TrustedProxies: proxies(t, "10.0.0.0/8")}, xfp: "https"},
		"no trusted proxies":              {cfg: apiauth.DPoPConfig{}, xfp: "https"},
		"pinned EndpointURL beats header": {cfg: apiauth.DPoPConfig{EndpointURL: "https://other.example/api/token", TrustedProxies: proxies(t, "192.0.2.0/24")}, xfp: "https"},
		"pinned BaseURL beats header":     {cfg: apiauth.DPoPConfig{BaseURL: "http://as.example.com", TrustedProxies: proxies(t, "192.0.2.0/24")}, xfp: "https"},
	} {
		t.Run(name, func(t *testing.T) {
			v := apiauth.NewDPoPProofValidator(tc.cfg)
			r := httptest.NewRequest(http.MethodPost, "http://as.example.com/api/token", nil)
			r.Header.Set("X-Forwarded-Proto", tc.xfp)
			r.Header.Set(apiauth.DPoPHeader, sign(proofOpts{url: "https://as.example.com/api/token"}))
			_, err := v.Confirm(context.Background(), r)
			if tc.wantOK {
				assert.NoError(t, err)
			} else {
				assertInvalidProof(t, err)
			}
		})
	}
}

func TestClientAssertionAudience_SchemeFromTrustedProxy(t *testing.T) {
	const aud = "https://as.example.com/api/token"
	for name, tc := range map[string]struct {
		trusted   core.TrustedProxies
		audiences []string
		xfp       string
		want      int
	}{
		"trusted proxy says https":             {trusted: proxies(t, "192.0.2.0/24"), xfp: "https", want: http.StatusOK},
		"trusted proxy says http":              {trusted: proxies(t, "192.0.2.0/24"), xfp: "http", want: http.StatusUnauthorized},
		"untrusted peer says https":            {trusted: proxies(t, "10.0.0.0/8"), xfp: "https", want: http.StatusUnauthorized},
		"no trusted proxies":                   {xfp: "https", want: http.StatusUnauthorized},
		"pinned AcceptedAudiences beat header": {trusted: proxies(t, "192.0.2.0/24"), audiences: []string{"https://pinned.example/token"}, xfp: "https", want: http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFAPIFixtureWith(t, false, func(c *apiauth.OneAuthConfig) {
				c.TrustedProxies = tc.trusted
				c.AcceptedAudiences = tc.audiences
			})
			rr := f.post(t, fapiReq{form: pkForm(f.assertion(t, aud)), headers: map[string]string{"X-Forwarded-Proto": tc.xfp}})
			assert.Equal(t, tc.want, rr.Code, rr.Body.String())
		})
	}
}

// The handlers OneAuth builds take its TrustedProxies, so one config field
// covers every endpoint that derives an audience.
func TestOneAuth_TrustedProxiesReachHandlers(t *testing.T) {
	tp := proxies(t, "192.0.2.0/24")
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		SigningKey: []byte("fapi-as-signing-key-that-is-32-b"), SigningAlg: "HS256",
		TrustedProxies: tp,
	})
	assert.Equal(t, tp, oa.TrustedProxies)
	assert.Equal(t, tp, apiauth.NewTokenEndpointHandler(oa).TrustedProxies)
	assert.Equal(t, tp, oa.IntrospectionHTTPHandler().TrustedProxies)
	assert.Equal(t, tp, oa.RevocationHTTPHandler().TrustedProxies)
}
