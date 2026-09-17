package apiauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/panyam/oneauth/core"
)

// DefaultPushedRequestExpiry is how long a request_uri stays usable.
// RFC 9126 §2.2 puts the typical range at 5 to 600 seconds and leaves the
// choice to the server. A minute covers a redirect and a user reading a
// consent screen, and bounds how long a stolen reference is worth
// anything.
const DefaultPushedRequestExpiry = 60 * time.Second

// pushedRequestEntropyBytes sizes the random part of a request_uri.
// RFC 9126 §2.2 requires a value that is computationally infeasible to
// guess, pointing at RFC 6749 §10.10; 32 bytes is the same budget the
// authorization codes in this package use.
const pushedRequestEntropyBytes = 32

// PARHandler serves the RFC 9126 pushed authorization request endpoint.
//
// A client POSTs the parameters it would otherwise put in a browser URL
// and gets back an opaque request_uri to redirect with. That keeps
// authorization parameters out of browser history, logs and Referer
// headers, and lets a request carry a payload too large for a URL, which
// is the practical reason RFC 9396 rich authorization requests want it.
//
// The handler validates the pushed parameters with the same code path
// /authorize uses, per §4 ("MUST validate authorization requests arising
// from a pushed request as it would any other").
type PARHandler struct {
	// Authorization supplies the validation rules and the store the
	// resolved request is written to. Required.
	Authorization *AuthorizationHandler

	// Store persists the pushed request. Required. Must be the same
	// store AuthorizationHandler.PushedStore reads, or a reference this
	// endpoint mints will not resolve at /authorize.
	Store core.PushedAuthorizationRequestStore

	// Authenticator authenticates the pushing client. §2 has the client
	// authenticate as it would at the token endpoint. Nil skips
	// authentication, which is only appropriate for a deployment whose
	// clients are all public (PKCE-only); FAPI profiles require
	// confidential clients here.
	Authenticator ClientAuthenticator

	// AppStore resolves the client registration that decides whether a
	// client_id is confidential. Nil treats every client as public.
	AppStore core.AppRegistrationStore

	// DPoP validates a proof sent on the push itself (RFC 9449 §10.1).
	// Nil accepts only the `dpop_jkt` parameter form.
	DPoP *DPoPProofValidator

	// Expiry overrides DefaultPushedRequestExpiry.
	Expiry time.Duration

	// AcceptedAudiences bounds the `aud` of a private_key_jwt or
	// client_secret_jwt client assertion (OIDC Core §9), as at the token
	// endpoint. Empty falls back to the request URL.
	AcceptedAudiences []string
}

// ServeHTTP handles POST /par.
//
// Errors use the token-endpoint error format (§2.3) rather than the
// authorization-endpoint redirect format, because a pushed request has no
// user agent to redirect: the client is talking to us directly and reads
// the JSON itself.
func (h *PARHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, &GrantError{Code: "invalid_request", Description: "method not allowed", Status: http.StatusMethodNotAllowed})
		return
	}
	if h.Authorization == nil || h.Store == nil {
		h.writeError(w, serverError("PAR endpoint is not configured"))
		return
	}
	if err := r.ParseForm(); err != nil {
		h.writeError(w, invalidRequest("could not parse form body"))
		return
	}

	// §2.1: request_uri is the one authorization parameter that must not
	// be pushed. Accepting it would let a client chain one reference to
	// another, and each hop is a place for the payload to change.
	if r.PostForm.Get("request_uri") != "" {
		h.writeError(w, invalidRequest("request_uri MUST NOT be included in a pushed authorization request"))
		return
	}

	clientID, gErr := h.authenticate(r)
	if gErr != nil {
		h.writeError(w, gErr)
		return
	}

	payload := pushedPayload(r.PostForm)
	payload.Set("client_id", clientID)

	confirmation, gErr := h.resolveDPoPBinding(r, payload)
	if gErr != nil {
		h.writeError(w, gErr)
		return
	}
	if confirmation != "" {
		payload.Set("dpop_jkt", confirmation)
	}

	if _, _, errCode, errDescription := h.Authorization.ValidateValues(r.Context(), payload); errCode != "" {
		h.writeError(w, &GrantError{Code: errCode, Description: errDescription, Status: http.StatusBadRequest})
		return
	}

	requestURI, err := generatePushedRequestURI()
	if err != nil {
		log.Printf("apiauth.PARHandler: generate request_uri: %v", err)
		h.writeError(w, serverError("could not create request_uri"))
		return
	}

	expiry := h.Expiry
	if expiry <= 0 {
		expiry = DefaultPushedRequestExpiry
	}
	now := time.Now()
	if _, err := h.Store.CreatePushedAuthorizationRequest(r.Context(), &core.CreatePushedAuthorizationRequestRequest{
		Request: &core.PushedAuthorizationRequest{
			RequestURI: requestURI,
			ClientID:   clientID,
			Payload:    payload,
			CreatedAt:  now,
			ExpiresAt:  now.Add(expiry),
		},
	}); err != nil {
		log.Printf("apiauth.PARHandler: store pushed request: %v", err)
		h.writeError(w, serverError("could not store the pushed request"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_uri": requestURI,
		"expires_in":  int64(expiry.Seconds()),
	})
}

// authenticate resolves the client behind the push.
//
// A confidential client must prove itself, the same as at the token
// endpoint. A public client presents only client_id, which §2.1 allows
// and PKCE covers. The client_id is required either way, since it is the
// value the request_uri gets bound to.
func (h *PARHandler) authenticate(r *http.Request) (string, *GrantError) {
	formClientID := r.PostForm.Get("client_id")

	creds, ok := extractClientCredentials(r, &core.TokenRequest{
		ClientID:            formClientID,
		ClientSecret:        r.PostForm.Get("client_secret"),
		ClientAssertion:     r.PostForm.Get("client_assertion"),
		ClientAssertionType: r.PostForm.Get("client_assertion_type"),
	})
	if !ok {
		creds = &AuthenticateClientRequest{ClientID: formClientID}
	}
	lookupID := creds.ClientID
	if lookupID == "" {
		lookupID = formClientID
	}
	if lookupID == "" {
		return "", invalidRequest("client_id is required")
	}

	authedID, err := authenticateConfidentialClient(r.Context(), h.AppStore, h.Authenticator, lookupID, clientCredentials{
		ClientID:            lookupID,
		ClientSecret:        creds.ClientSecret,
		ClientAssertionType: creds.ClientAssertionType,
		ClientAssertion:     creds.ClientAssertion,
		Audiences:           h.acceptedAudiences(r),
	})
	if err != nil {
		if ge, isGrantErr := asGrantError(err); isGrantErr {
			return "", ge
		}
		return "", invalidClient(err.Error())
	}
	if authedID != "" {
		return authedID, nil
	}
	return lookupID, nil
}

// resolveDPoPBinding implements RFC 9449 §10.1, which has an authorization
// server supporting both PAR and DPoP accept the key two ways: as the
// `dpop_jkt` parameter in the pushed body, or as a DPoP proof on the push
// itself. A proof is the stronger of the two, since it demonstrates
// possession rather than naming a thumbprint anyone could copy.
//
// Both may appear, and §10.1 requires rejecting the request when they
// disagree. Returning the thumbprint to store means the rest of the flow
// treats a header-bound push exactly like a `dpop_jkt` one.
func (h *PARHandler) resolveDPoPBinding(r *http.Request, payload url.Values) (string, *GrantError) {
	pushedJKT := payload.Get("dpop_jkt")
	if h.DPoP == nil || r.Header.Get(DPoPHeader) == "" {
		return pushedJKT, nil
	}

	confirmation, err := h.DPoP.Confirm(r.Context(), r)
	if err != nil {
		if ge, ok := asGrantError(err); ok {
			return "", ge
		}
		return "", invalidDPoPProof(err.Error())
	}
	if confirmation == nil {
		return pushedJKT, nil
	}
	if pushedJKT != "" && pushedJKT != confirmation.JKT {
		return "", invalidRequest("dpop_jkt does not match the key in the DPoP proof")
	}
	return confirmation.JKT, nil
}

func (h *PARHandler) acceptedAudiences(r *http.Request) []string {
	if len(h.AcceptedAudiences) > 0 {
		return h.AcceptedAudiences
	}
	return []string{derivedAudience(r)}
}

func (h *PARHandler) writeError(w http.ResponseWriter, err *GrantError) {
	status := err.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             err.Code,
		"error_description": err.Description,
	})
}

// pushedPayload copies the authorization parameters out of the posted
// form, dropping the ones that authenticate the client rather than
// describe the request.
//
// §2.1 says client-authentication parameters "are relied upon only for
// client authentication and are not germane to the authorization request
// itself". Storing a client_secret alongside the request would leave a
// credential sitting in the store for the reference's lifetime, for no
// benefit.
func pushedPayload(form url.Values) url.Values {
	authOnly := map[string]bool{
		"client_secret":         true,
		"client_assertion":      true,
		"client_assertion_type": true,
	}
	payload := url.Values{}
	for key, values := range form {
		if authOnly[key] {
			continue
		}
		payload[key] = append([]string(nil), values...)
	}
	return payload
}

// generatePushedRequestURI returns a fresh reference in the URN form
// RFC 9126 §2.2 suggests, with a CSPRNG-generated random part.
func generatePushedRequestURI() (string, error) {
	raw := make([]byte, pushedRequestEntropyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("could not read random bytes for request_uri")
	}
	return core.PushedRequestURIPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
