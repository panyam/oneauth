package apiauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
)

// Authorization code lifetime + entropy. RFC 6749 §4.1.2 recommends
// codes expire in 10 minutes or less; OAuth 2.1 narrows this further.
// We default to 60 seconds — generous for a same-tab redirect flow,
// tight enough that a stolen code is rarely usable.
const (
	// DefaultAuthorizationCodeExpiry is the lifetime applied to minted
	// authorization codes when AuthorizationHandler.Expiry is unset.
	DefaultAuthorizationCodeExpiry = 60 * time.Second

	// authorizationCodeBytes is the entropy budget for the high-entropy
	// code returned to the client. 256 bits ⇒ unguessable in any
	// practical attacker timeframe.
	authorizationCodeBytes = 32

	// AuthorizationCodeGrantType is the OAuth 2.0 grant type identifier
	// for the authorization-code grant. The token endpoint dispatches
	// `grant_type=authorization_code` to handleAuthorizationCodeGrant.
	AuthorizationCodeGrantType = "authorization_code"
)

// AuthorizationRequest is the parsed RFC 6749 §4.1.1 authorization
// request shape. The handler validates it once on GET (to render
// consent) and again on POST (to defend against tampered hidden
// inputs), so the type is exported for the verification handler to
// share.
type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string

	// DPoPJKT is the RFC 9449 §10 `dpop_jkt` parameter: the RFC 7638
	// thumbprint of the key the client will prove at the token
	// endpoint. Optional; empty leaves the issued code unbound.
	DPoPJKT string

	// RequestURI is the RFC 9126 reference this request was resolved
	// from, empty for a request whose parameters arrived in the URL.
	// IssueCode consumes it once a code has been minted, which is what
	// makes a pushed reference good for one authorization.
	RequestURI string
}

// Scopes returns the request's scope claim split on the RFC 6749
// space-delimited form.
func (r *AuthorizationRequest) Scopes() []string {
	return core.ParseScopes(r.Scope)
}

// AuthorizationHandler validates RFC 6749 §4.1 authorization requests
// and emits the §4.1.2 redirect response. The handler is request-only
// — it does NOT render a consent screen. The verification handler
// (AuthorizeVerificationHandler) drives the human-side surface and
// calls AuthorizationHandler.IssueCode on Approve.
//
// Most production deployments mount this via MountAuthorize, which
// wires the verification handler in front so the flow is end-to-end.
// Tests that only need the wire-shape (e.g. RFC 9207 iss emission)
// can call IssueCode directly.
type AuthorizationHandler struct {
	// Store persists minted codes. Required.
	Store core.AuthorizationCodeStore

	// AppStore validates the (client_id, redirect_uri) tuple. When nil
	// the handler accepts any (client_id, redirect_uri) pair — suitable
	// for in-process tests, NOT for production. RedirectURIValidator
	// overrides this lookup when set.
	AppStore core.AppRegistrationStore

	// RedirectURIValidator, when non-nil, owns the (client_id,
	// redirect_uri) allowlist check. Overrides AppStore-based
	// validation. Use for deployments whose redirect_uri registry
	// lives outside AppStore. Return nil to accept; return an error to
	// reject (the error message goes to the user — keep it generic).
	RedirectURIValidator func(ctx context.Context, clientID, redirectURI string) error

	// IssuerURL is the AS's issuer identifier. When EmitIssParameter is
	// true the handler appends `iss=<IssuerURL>` to the redirect per
	// RFC 9207 §2. Required when EmitIssParameter is true; otherwise
	// optional.
	IssuerURL string

	// EmitIssParameter toggles RFC 9207 `iss` emission on the redirect.
	// Pair with ASServerMetadata.AuthorizationResponseIssParameterSupported
	// so the AS's advertisement matches the wire behavior.
	EmitIssParameter bool

	// RedirectOverride, when non-nil, is called with the redirect's
	// query values just before they are URL-encoded and the redirect
	// is sent. Lets conformance scenarios mutate / strip / corrupt
	// individual values (e.g. drop iss to test client behavior when
	// the AS advertises but does not emit). Production deployments
	// leave this nil.
	RedirectOverride func(values url.Values)

	// Expiry overrides DefaultAuthorizationCodeExpiry.
	Expiry time.Duration

	// AllowPlainPKCE permits `code_challenge_method=plain` per
	// RFC 7636 §4.4. OAuth 2.1 §7.5 retired plain; leaving this false
	// (default) keeps OneAuth's /authorize strict-2.1 — only S256 is
	// accepted, advertised, and verified at redemption. Operators
	// setting this true take on responsibility for the leak surface
	// the §7.5 retirement was meant to close: a plain `code_challenge`
	// IS the verifier, so any leaked authorization request equals a
	// leaked verifier. Set on OneAuthConfig.AllowPlainPKCE so the AS
	// metadata derivation and the redemption path can read the same
	// value.
	//
	// Per capability-gating umbrella #344.
	AllowPlainPKCE bool

	// allowPlainPKCEWarning fires once per AuthorizationHandler
	// instance the first time a plain code_challenge is accepted at
	// runtime. Surfaces the OAuth 2.0 escape hatch to operators who
	// may have set the flag and forgotten.
	allowPlainPKCEWarning sync.Once

	// PushedStore resolves RFC 9126 `request_uri` references. Nil makes
	// the endpoint reject any request carrying one, which is the right
	// answer for a deployment that does not run a PAR endpoint.
	PushedStore core.PushedAuthorizationRequestStore

	// RequirePushedRequests refuses any authorization request that did
	// not arrive through the PAR endpoint (RFC 9126 §4, "Authorization
	// server policy MAY dictate... that PAR be the only means"). Pair it
	// with `require_pushed_authorization_requests` in AS metadata so
	// clients learn the policy before hitting it.
	RequirePushedRequests bool
}

// ParseAndValidate parses an HTTP request's query / form into an
// AuthorizationRequest, applies the RFC 6749 §4.1.1 syntax checks, and
// validates the (client_id, redirect_uri) tuple against the configured
// AppStore / RedirectURIValidator.
//
// Two kinds of error are distinguished:
//
//   - "MUST 400" errors (`client_id` / `redirect_uri` syntactically
//     missing or unregistered) — these are returned with displayErr=true
//     and MUST NOT be redirected back to the client per RFC 6749 §4.1.2.1
//     ("the authorization server SHOULD inform the resource owner of the
//     error… do NOT redirect"). The caller renders an HTML error page.
//
//   - "MAY redirect" errors (everything else: invalid response_type,
//     missing PKCE, etc.) — these are returned with displayErr=false
//     and an OAuth error code that the caller propagates to the
//     redirect_uri per RFC 6749 §4.1.2.1.
//
// On success returns the parsed request and (nil, "", false).
func (h *AuthorizationHandler) ParseAndValidate(r *http.Request) (req *AuthorizationRequest, displayErr bool, errCode, errDescription string) {
	// GET reads from query; POST reads from form (the consent screen
	// posts the request back as hidden inputs).
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, true, "invalid_request", "could not parse form body"
		}
		values = r.PostForm
	}

	requestURI := strings.TrimSpace(values.Get("request_uri"))
	if requestURI == "" {
		if h.RequirePushedRequests {
			return nil, true, "invalid_request", "this server accepts authorization requests only through the pushed authorization request endpoint (RFC 9126)"
		}
		return h.ValidateValues(r.Context(), values)
	}

	pushed, displayErr, errCode, errDescription := h.resolvePushedRequest(r.Context(), requestURI, strings.TrimSpace(values.Get("client_id")))
	if errCode != "" {
		return nil, displayErr, errCode, errDescription
	}
	// The stored payload is authoritative. Anything else the browser
	// carried is ignored rather than merged, which is what makes a
	// pushed request tamper-proof between the push and the redirect:
	// the consent screen's own hidden inputs cannot override it either.
	req, displayErr, errCode, errDescription = h.ValidateValues(r.Context(), pushed.Payload)
	if req != nil {
		req.RequestURI = requestURI
	}
	return req, displayErr, errCode, errDescription
}

// resolvePushedRequest looks up a `request_uri` and checks the three
// conditions RFC 9126 §4 puts on it: the reference must exist, must not
// have expired, and must belong to the client presenting it. A reference
// whose code has already been issued is refused as used.
//
// Every failure here is a display error rather than a redirect. The
// parameters that would tell us where to redirect live inside the record
// we just failed to trust, so redirecting would mean trusting a
// client_id and redirect_uri that arrived in the browser URL.
func (h *AuthorizationHandler) resolvePushedRequest(ctx context.Context, requestURI, clientID string) (pushed *core.PushedAuthorizationRequest, displayErr bool, errCode, errDescription string) {
	if h.PushedStore == nil {
		return nil, true, "invalid_request", "request_uri is not supported by this server"
	}
	resp, err := h.PushedStore.GetPushedAuthorizationRequest(ctx, &core.GetPushedAuthorizationRequestRequest{RequestURI: requestURI})
	if err != nil {
		if errors.Is(err, core.ErrPushedRequestNotFound) {
			return nil, true, "invalid_request", "unknown request_uri"
		}
		return nil, true, "server_error", "could not resolve request_uri"
	}
	record := resp.Request
	if record.IsExpired(time.Now()) {
		return nil, true, "invalid_request", "request_uri has expired"
	}
	if record.Consumed {
		return nil, true, "invalid_request", "request_uri has already been used"
	}
	// §2.2 binds the reference to the client that pushed it. A client_id
	// in the URL that disagrees means someone is trying to spend another
	// client's pushed request.
	if clientID != "" && clientID != record.ClientID {
		return nil, true, "invalid_request", "request_uri was not issued to this client"
	}
	return record, false, "", ""
}

// ValidateValues applies the RFC 6749 §4.1.1 syntax checks and the
// (client_id, redirect_uri) registration check to an already-extracted
// parameter set.
//
// It is exported so the PAR endpoint can run the same validation on a
// pushed request that /authorize runs on a redirected one. RFC 9126 §4
// requires exactly that ("MUST validate authorization requests arising
// from a pushed request as it would any other"), and sharing the function
// is what keeps the two from drifting.
func (h *AuthorizationHandler) ValidateValues(ctx context.Context, values url.Values) (req *AuthorizationRequest, displayErr bool, errCode, errDescription string) {
	req = &AuthorizationRequest{
		ClientID:            strings.TrimSpace(values.Get("client_id")),
		RedirectURI:         strings.TrimSpace(values.Get("redirect_uri")),
		ResponseType:        strings.TrimSpace(values.Get("response_type")),
		Scope:               values.Get("scope"),
		State:               values.Get("state"),
		CodeChallenge:       strings.TrimSpace(values.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(values.Get("code_challenge_method")),
		DPoPJKT:             strings.TrimSpace(values.Get("dpop_jkt")),
	}

	// RFC 6749 §4.1.2.1 — missing client_id / redirect_uri is a
	// "display, do not redirect" error.
	if req.ClientID == "" {
		return req, true, "invalid_request", "client_id is required"
	}
	if req.RedirectURI == "" {
		return req, true, "invalid_request", "redirect_uri is required"
	}

	// Validate (client_id, redirect_uri) against the configured
	// registry. Same "display, do not redirect" rule — an unregistered
	// redirect_uri MUST NOT receive the error (per §4.1.2.1) because
	// it might be attacker-controlled.
	if err := h.validateRedirectURI(ctx, req.ClientID, req.RedirectURI); err != nil {
		return req, true, "unauthorized_client", err.Error()
	}

	// From here on, errors flow back to the client via the redirect
	// (§4.1.2.1 "MAY include state" — preserved by the caller).
	if req.ResponseType != "code" {
		return req, false, "unsupported_response_type", "only response_type=code is supported"
	}

	if req.CodeChallenge == "" {
		// OAuth 2.1 mandates PKCE for all clients; even pre-2.1 we
		// require it because public clients cannot prove identity
		// without it.
		return req, false, "invalid_request", "code_challenge is required (PKCE)"
	}
	if req.CodeChallengeMethod == "" {
		// RFC 7636 §4.3 defaults to "plain" when omitted. We require
		// the method to be sent explicitly so the client's intent is
		// unambiguous on the wire — and so a misconfigured client
		// doesn't accidentally pick the weaker method.
		return req, false, "invalid_request", "code_challenge_method is required"
	}
	switch req.CodeChallengeMethod {
	case core.CodeChallengeMethodS256:
		// OAuth 2.1 §7.5 mandated default; always accepted.
	case core.CodeChallengeMethodPlain:
		if !h.AllowPlainPKCE {
			return req, false, "invalid_request", "only S256 PKCE is supported (set OneAuthConfig.AllowPlainPKCE to permit plain for OAuth 2.0 fleets)"
		}
		h.allowPlainPKCEWarning.Do(func() {
			log.Printf("apiauth.AuthorizationHandler: LEGACY OAuth 2.0 PATH — code_challenge_method=plain accepted. " +
				"OAuth 2.1 §7.5 retired plain; the challenge equals the verifier, so any leaked authorization " +
				"request equals a leaked verifier. Disable by leaving OneAuthConfig.AllowPlainPKCE false.")
		})
	default:
		return req, false, "invalid_request", fmt.Sprintf("unsupported code_challenge_method=%q", req.CodeChallengeMethod)
	}

	return req, false, "", ""
}

// IssueCode mints + persists a fresh authorization code bound to the
// supplied (request, subject) tuple. The caller (the consent
// verification handler) calls this on Approve. Returns the code on
// success.
func (h *AuthorizationHandler) IssueCode(ctx context.Context, req *AuthorizationRequest, subject string, grantedScopes []string) (string, error) {
	code, err := generateAuthorizationCode()
	if err != nil {
		return "", err
	}
	now := time.Now()
	expiry := h.Expiry
	if expiry <= 0 {
		expiry = DefaultAuthorizationCodeExpiry
	}
	scopes := grantedScopes
	if scopes == nil {
		scopes = req.Scopes()
	}
	entry := &core.AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scopes:              scopes,
		Subject:             subject,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		DPoPJKT:             req.DPoPJKT,
		IssuedAt:            now,
		ExpiresAt:           now.Add(expiry),
	}
	if _, err := h.Store.CreateAuthorizationCode(ctx, &core.CreateAuthorizationCodeRequest{Code: entry}); err != nil {
		return "", err
	}

	// A pushed reference is spent when it produces a code, not when it
	// is first read (RFC 9126 §4). Reading it twice is ordinary: the
	// consent screen renders on GET and approves on POST, and a user who
	// reloads before approving has done nothing wrong. Consuming here
	// keeps "one code per pushed request" while leaving that alone.
	//
	// A failure to consume is logged rather than fatal: the code is
	// already minted and the client is entitled to it. The reference
	// expires on its own within a minute.
	if req.RequestURI != "" && h.PushedStore != nil {
		if _, err := h.PushedStore.ConsumePushedAuthorizationRequest(ctx, &core.ConsumePushedAuthorizationRequestRequest{RequestURI: req.RequestURI}); err != nil {
			log.Printf("apiauth.AuthorizationHandler: could not consume request_uri %q after issuing a code: %v", req.RequestURI, err)
		}
	}
	return code, nil
}

// SuccessRedirect composes the RFC 6749 §4.1.2 success redirect URL:
//
//	<redirect_uri>?code=<code>[&state=<state>][&iss=<iss>]
//
// Honors EmitIssParameter (RFC 9207) and RedirectOverride
// (conformance hook).
func (h *AuthorizationHandler) SuccessRedirect(req *AuthorizationRequest, code string) (string, error) {
	values := url.Values{}
	values.Set("code", code)
	if req.State != "" {
		values.Set("state", req.State)
	}
	if h.EmitIssParameter && h.IssuerURL != "" {
		values.Set("iss", h.IssuerURL)
	}
	if h.RedirectOverride != nil {
		h.RedirectOverride(values)
	}
	return appendQuery(req.RedirectURI, values)
}

// ErrorRedirect composes the RFC 6749 §4.1.2.1 error redirect URL:
//
//	<redirect_uri>?error=<code>[&error_description=...][&state=<state>][&iss=<iss>]
//
// Used by the verification handler to report user-deny and
// post-validation failures.
func (h *AuthorizationHandler) ErrorRedirect(req *AuthorizationRequest, errCode, errDescription string) (string, error) {
	values := url.Values{}
	values.Set("error", errCode)
	if errDescription != "" {
		values.Set("error_description", errDescription)
	}
	if req.State != "" {
		values.Set("state", req.State)
	}
	if h.EmitIssParameter && h.IssuerURL != "" {
		values.Set("iss", h.IssuerURL)
	}
	if h.RedirectOverride != nil {
		h.RedirectOverride(values)
	}
	return appendQuery(req.RedirectURI, values)
}

func (h *AuthorizationHandler) validateRedirectURI(ctx context.Context, clientID, redirectURI string) error {
	if h.RedirectURIValidator != nil {
		return h.RedirectURIValidator(ctx, clientID, redirectURI)
	}
	if h.AppStore == nil {
		return nil
	}
	resp, err := h.AppStore.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	if err != nil || resp == nil || resp.App == nil {
		return errInvalidClientOrRedirect
	}
	// Empty registered redirect_uris means the AS hasn't recorded one
	// for this client — fail closed so a typo'd registration cannot
	// silently forward codes to an attacker.
	if len(resp.App.RedirectURIs) == 0 {
		return errInvalidClientOrRedirect
	}
	for _, allowed := range resp.App.RedirectURIs {
		if allowed == redirectURI {
			return nil
		}
	}
	return errInvalidClientOrRedirect
}

// generateAuthorizationCode returns a 256-bit hex-encoded code.
func generateAuthorizationCode() (string, error) {
	b := make([]byte, authorizationCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// appendQuery appends values to base's query string, preserving any
// existing params. Returns the encoded URL.
func appendQuery(base string, values url.Values) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, vs := range values {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// errInvalidClientOrRedirect is the sentinel ParseAndValidate uses to
// signal the §4.1.2.1 "do not redirect" path. The message is
// deliberately generic so a probing attacker cannot tell whether the
// client_id or the redirect_uri was at fault.
var errInvalidClientOrRedirect = newAuthorizeError("unknown client_id or redirect_uri")

type authorizeError struct{ msg string }

func (e *authorizeError) Error() string { return e.msg }

func newAuthorizeError(msg string) error { return &authorizeError{msg: msg} }
