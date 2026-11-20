package apiauth

import (
	"net/http"

	"github.com/panyam/oneauth/core"
)

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
// r.ParseForm() or r.ParseMultipartForm() before calling). Form fields
// come from the body only: RFC 6749 §2.3.1 keeps credentials out of the
// request URI, and checkFormParams refuses them there (issue 519). When
// req is non-nil (the token endpoint, which may have decoded a JSON
// body), it is the fallback for fields absent from the form and header.
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
		fAssertion     = r.PostFormValue("client_assertion")
		fAssertionType = r.PostFormValue("client_assertion_type")
		fClientID      = r.PostFormValue("client_id")
		fClientSecret  = r.PostFormValue("client_secret")
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
// The scheme is https when r.TLS is set and http otherwise; forwarded
// headers are ignored (see the body).
func derivedAudience(r *http.Request) string {
	// X-Forwarded-Proto / X-Forwarded-Host are not read: anyone can send
	// them, and letting a caller choose the audience its own assertion is
	// checked against would accept an assertion minted for another server
	// (CWE-346). Behind a proxy, set AcceptedAudiences.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}
