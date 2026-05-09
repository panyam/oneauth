package apiauth

import (
	"errors"
	"net/http"

	"github.com/panyam/oneauth/core"
)

// errMissingClientCredentials reports that a request to a token-endpoint /
// introspection / revocation handler carried no client credentials in any
// of the recognized channels. The token endpoint maps this to RFC 6749
// §5.2 invalid_request (HTTP 400, missing required parameter); the other
// endpoints prefer the more conservative invalid_client (HTTP 401) since
// the absence of credentials is itself an authentication failure for them.
var errMissingClientCredentials = errors.New("missing client credentials")

// extractClientCredentials inspects r for client credentials per the
// three OAuth-defined channels:
//
//  1. private_key_jwt / client_secret_jwt — RFC 7521 §4.2 form params
//     client_assertion + client_assertion_type
//  2. client_secret_basic — RFC 6749 §2.3.1 Authorization: Basic header
//  3. client_secret_post — RFC 6749 §2.3.1 form params client_id +
//     client_secret
//
// Channel 1 takes precedence (strongest credential), then 2, then 3.
// RFC 6749 §2.3 says a client "MUST NOT use more than one
// authentication method in each request"; if a confused or malicious
// client sends both, we pick the strongest signal and ignore the rest.
//
// The form is assumed already parsed (handler must have called
// r.ParseForm() or r.ParseMultipartForm() before calling). When
// req is non-nil (token endpoint, where the body has already been
// decoded into a core.TokenRequest — possibly from a JSON body that
// http.Request.FormValue can't see), it is used as a fallback for
// fields not present in the form/header.
//
// Returns the populated request and true on success; nil + false when
// no credentials are present.
func extractClientCredentials(r *http.Request, req *core.TokenRequest) (*AuthenticateClientRequest, bool) {
	formValue := func(form, fallback string) string {
		if form != "" {
			return form
		}
		return fallback
	}
	var (
		fAssertion     = r.FormValue("client_assertion")
		fAssertionType = r.FormValue("client_assertion_type")
		fClientID      = r.FormValue("client_id")
		fClientSecret  = r.FormValue("client_secret")
	)
	var (
		jAssertion, jAssertionType, jClientID, jClientSecret string
	)
	if req != nil {
		jAssertion = req.ClientAssertion
		jAssertionType = req.ClientAssertionType
		jClientID = req.ClientID
		jClientSecret = req.ClientSecret
	}

	assertion := formValue(fAssertion, jAssertion)
	if assertion != "" {
		return &AuthenticateClientRequest{
			ClientID:            formValue(fClientID, jClientID),
			ClientAssertionType: formValue(fAssertionType, jAssertionType),
			ClientAssertion:     assertion,
		}, true
	}
	if user, pass, ok := r.BasicAuth(); ok && user != "" {
		return &AuthenticateClientRequest{
			ClientID:     user,
			ClientSecret: pass,
		}, true
	}
	id := formValue(fClientID, jClientID)
	secret := formValue(fClientSecret, jClientSecret)
	if id != "" && secret != "" {
		return &AuthenticateClientRequest{
			ClientID:     id,
			ClientSecret: secret,
		}, true
	}
	return nil, false
}

// derivedAudience returns the absolute URL of the endpoint serving r.
// Used as a fallback when handlers haven't been configured with an
// explicit AcceptedAudiences list. Per OIDC Core §9 the audience SHOULD
// be the AS endpoint URL the client is calling.
//
// Scheme detection prefers X-Forwarded-Proto (set by reverse proxies)
// and falls back to https when r.TLS is set, http otherwise.
func derivedAudience(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}
	return scheme + "://" + host + r.URL.Path
}
