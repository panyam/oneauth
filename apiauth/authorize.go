package apiauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/httpauth"
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

	// ResponseMode is the `response_mode` parameter as sent: query,
	// fragment or form_post, or empty for the response type's default
	// (Multiple Response Type Encoding Practices §2.1). ValidateValues
	// refuses any other value, and query for the implicit types.
	ResponseMode string

	// DPoPJKT is the RFC 9449 §10 `dpop_jkt` parameter: the RFC 7638
	// thumbprint of the key the client will prove at the token
	// endpoint. Optional; empty leaves the issued code unbound.
	DPoPJKT string

	// RequestURI is the RFC 9126 reference this request was resolved
	// from, empty for a request whose parameters arrived in the URL.
	// IssueCode consumes it once a code has been minted, which is what
	// makes a pushed reference good for one authorization.
	RequestURI string

	// Nonce is the OIDC Core §3.1.2.1 `nonce` parameter. The code carries
	// it to the token endpoint, which echoes it in the ID token. Optional;
	// empty when the client sent none.
	Nonce string

	// Claims is the OIDC Core §5.5 `claims` parameter as sent, a JSON
	// object. The consent form posts it back verbatim. IDTokenClaims and
	// UserinfoClaims are the claim names it asks for in each place, which
	// the code carries to the token endpoint. All empty when the client
	// sent none.
	Claims         string
	IDTokenClaims  []string
	UserinfoClaims []string

	// Prompt is the OIDC Core §3.1.2.1 `prompt` parameter, split on
	// spaces: "none", "login", "consent" or "select_account". Empty when
	// the client sent none. ValidateValues refuses "none" alongside any
	// other value.
	Prompt []string

	// MaxAge is the OIDC Core §3.1.2.1 `max_age` parameter: the most
	// seconds since the user last logged in that the client accepts. Nil
	// when the client sent none.
	MaxAge *int64

	// AuthTime is when the approving user last authenticated. It does not
	// come from the request: the verification handler sets it from
	// AuthTimeFromRequest before IssueCode, and the ID token reports it as
	// `auth_time`. Zero leaves the claim out.
	AuthTime time.Time

	// ACRValues is the OIDC Core §3.1.2.1 `acr_values` parameter split on
	// spaces, in the client's order of preference. Empty when the client
	// sent none.
	ACRValues []string

	// ACR and AMR are how the approving user authenticated, the ID
	// token's `acr` and `amr`. Like AuthTime they don't come from the
	// request: the verification handler sets them from
	// AuthContextFromRequest before IssueCode. Empty leaves them out.
	ACR string
	AMR []string

	// Resources are the RFC 8707 `resource` parameters, each checked
	// against AuthorizationHandler.AllowedResources. The code carries them
	// to the token endpoint. Empty when the client sent none or the
	// handler has no allowlist.
	Resources []string
}

// AuthContext is how the logged-in user authenticated, reported in the
// ID token (OIDC Core §2). ACR is the authentication context class the
// login met, and AMR lists the methods it used, with RFC 8176 values such
// as "pwd", "otp" or "mfa". Empty fields are left out of the ID token.
type AuthContext struct {
	ACR string
	AMR []string
}

// HasPrompt reports whether the request's `prompt` includes value.
func (r *AuthorizationRequest) HasPrompt(value string) bool {
	return slices.Contains(r.Prompt, value)
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

	// AllowedResources is OneAuthConfig.AllowedResources. A request whose
	// `resource` it doesn't list is refused with invalid_target at the
	// redirect URI (RFC 8707 §2). Empty ignores `resource`.
	AllowedResources []string

	// AllowAnyRedirectURI accepts any redirect_uri when neither AppStore
	// nor RedirectURIValidator is set. Without it such a handler refuses
	// every request, since it has nothing to check redirect_uri against
	// and would otherwise send codes wherever the request said (CWE-601).
	// For test fixtures and conformance harnesses only.
	AllowAnyRedirectURI bool

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

	// PKCEPolicy says which clients may omit code_challenge; see
	// PKCEPolicy. MountAuthorize copies OneAuthConfig.PKCEPolicy here.
	PKCEPolicy PKCEPolicy

	// allowPlainPKCEWarning fires once per AuthorizationHandler
	// instance the first time a plain code_challenge is accepted at
	// runtime. Surfaces the OAuth 2.0 escape hatch to operators who
	// may have set the flag and forgotten.
	allowPlainPKCEWarning sync.Once

	// PushedStore resolves RFC 9126 `request_uri` references. Nil makes
	// the endpoint reject any request carrying one, which is the right
	// answer for a deployment that does not run a PAR endpoint.
	PushedStore core.PushedAuthorizationRequestStore

	// Implicit serves the OIDC implicit response types when set (OIDC Core
	// §3.2, issue 507). MountAuthorize sets it from
	// OneAuthConfig.AllowImplicit. Nil refuses them as before.
	Implicit *ImplicitTokens

	// RequirePushedRequests refuses any authorization request that did
	// not arrive through the PAR endpoint (RFC 9126 §4, "Authorization
	// server policy MAY dictate... that PAR be the only means"). Pair it
	// with `require_pushed_authorization_requests` in AS metadata so
	// clients learn the policy before hitting it.
	RequirePushedRequests bool

	// ResponseSigner signs responses for the JARM response modes (jwt,
	// query.jwt, fragment.jwt, form_post.jwt), which h accepts only when
	// it is set. MountAuthorize sets it from OneAuthConfig.JARM.
	//
	// See: https://openid.net/specs/oauth-v2-jarm.html
	ResponseSigner AuthorizationResponseSigner
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
		httpauth.CapRequestBody(nil, r)
		if err := r.ParseForm(); err != nil {
			return nil, true, "invalid_request", "could not parse form body"
		}
		values = r.PostForm
	}

	// RFC 6749 §3.1: no parameter may repeat. A repeated client_id or
	// redirect_uri leaves no redirect to trust, so the page shows it;
	// anything else goes back to the client as invalid_request.
	if p := repeatedParam(values); p != "" {
		desc := p + " must not be included more than once (RFC 6749 §3.1)"
		if p == "client_id" || p == "redirect_uri" {
			return nil, true, "invalid_request", desc
		}
		req, displayErr, _, _ = h.validateClientAndRedirect(r.Context(), values)
		return req, displayErr, "invalid_request", desc
	}

	requestURI := strings.TrimSpace(values.Get("request_uri"))
	if requestURI != "" && (h.PushedStore == nil || !strings.HasPrefix(requestURI, core.PushedRequestURIPrefix)) {
		// OIDC Core §6.2: oneauth resolves only the references its own
		// PAR endpoint issued. When the outer parameters name a registered
		// redirect URI, the client hears request_uri_not_supported there,
		// with its state; otherwise the page shows it.
		req, displayErr, _, _ = h.validateClientAndRedirect(r.Context(), values)
		return req, displayErr, "request_uri_not_supported", "request_uri is not supported here: this server resolves only references from its own pushed authorization request endpoint"
	}
	if requestURI == "" {
		if h.RequirePushedRequests {
			return nil, true, "invalid_request", "this server accepts authorization requests only through the pushed authorization request endpoint (RFC 9126)"
		}
		// RFC 9126 §6: a client can register to be held to PAR on its own.
		reg, gErr := clientRegistration(r.Context(), h.AppStore, strings.TrimSpace(values.Get("client_id")))
		if gErr != nil {
			return nil, true, gErr.Code, "could not load the client registration"
		}
		if reg != nil && reg.RequirePushedAuthorizationRequests {
			return nil, true, "invalid_request", "this client is registered to send authorization requests only through the pushed authorization request endpoint (RFC 9126 §6)"
		}
		return h.ValidateValues(r.Context(), values)
	}

	// RFC 9126 §4: client_id is REQUIRED alongside request_uri, so the
	// reference can be checked against the client presenting it.
	clientID := strings.TrimSpace(values.Get("client_id"))
	if clientID == "" {
		return nil, true, "invalid_request", "client_id is required with request_uri"
	}
	pushed, displayErr, errCode, errDescription := h.resolvePushedRequest(r.Context(), requestURI, clientID)
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
	if clientID != record.ClientID {
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
	req, displayErr, errCode, errDescription = h.validateClientAndRedirect(ctx, values)
	// OIDC Core §6.1: oneauth doesn't support request objects. Refusing
	// one, rather than ignoring it, keeps the client from losing the
	// object's state and nonce. The error goes to the redirect URI when
	// the outer parameters name a registered one, as §6.1 expects.
	if values.Has("request") {
		return req, displayErr, "request_not_supported", "this server does not support request objects (the request parameter)"
	}
	if errCode != "" {
		return req, displayErr, errCode, errDescription
	}

	// From here on, errors flow back to the client via the redirect
	// (§4.1.2.1 "MAY include state" — preserved by the caller).
	implicit := h.isImplicit(req)
	if req.ResponseType != "code" && !implicit {
		return req, false, "unsupported_response_type", "only response_type=code is supported"
	}

	if code, desc := h.checkResponseMode(req); code != "" {
		return req, false, code, desc
	}

	// PKCE protects the code exchange, which the implicit flow doesn't
	// have; its nonce binds the ID token instead.
	if !implicit {
		if code, desc := h.validatePKCE(ctx, req); code != "" {
			return req, false, code, desc
		}
	}

	if code, desc := parsePromptAndMaxAge(req, values); code != "" {
		return req, false, code, desc
	}

	if code, desc := parseClaimsParam(req, values); code != "" {
		return req, false, code, desc
	}

	resources, gErr := checkResources(h.AllowedResources, values["resource"])
	if gErr != nil {
		return req, false, gErr.Code, gErr.Description
	}
	req.Resources = resources

	// The client's registered scope bounds what it can ask for (RFC 6749
	// §3.3), the same rule the token endpoint applies, and asking for
	// nothing gets the registered default.
	reg, gErr := clientRegistration(ctx, h.AppStore, req.ClientID)
	if gErr != nil {
		return req, true, gErr.Code, "could not load the client registration"
	}
	scopes, gErr := grantScopes(reg, req.Scopes())
	if gErr != nil {
		return req, false, gErr.Code, gErr.Description
	}
	req.Scope = core.JoinScopes(scopes)

	if implicit {
		if code, desc := validateImplicit(req, reg); code != "" {
			return req, false, code, desc
		}
	}
	return req, false, "", ""
}

// validateClientAndRedirect reads the request's parameters and checks the
// two that decide where an error may go: client_id, and a redirect_uri
// registered for it. Every failure is a display error (displayErr true),
// since RFC 6749 §4.1.2.1 forbids redirecting to an unchecked redirect
// URI, so a caller may report its own error with the displayErr it gets.
func (h *AuthorizationHandler) validateClientAndRedirect(ctx context.Context, values url.Values) (req *AuthorizationRequest, displayErr bool, errCode, errDescription string) {
	req = &AuthorizationRequest{
		ClientID:            strings.TrimSpace(values.Get("client_id")),
		RedirectURI:         strings.TrimSpace(values.Get("redirect_uri")),
		ResponseType:        strings.TrimSpace(values.Get("response_type")),
		Scope:               values.Get("scope"),
		State:               values.Get("state"),
		CodeChallenge:       strings.TrimSpace(values.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(values.Get("code_challenge_method")),
		ResponseMode:        strings.TrimSpace(values.Get("response_mode")),
		DPoPJKT:             strings.TrimSpace(values.Get("dpop_jkt")),
		Nonce:               values.Get("nonce"),
		ACRValues:           strings.Fields(values.Get("acr_values")),
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
	return req, false, "", ""
}

// validatePKCE checks the request's code_challenge and method (RFC 7636)
// and returns an OAuth error code and description, or two empty strings
// when the request may go ahead. A request without a challenge goes ahead
// only under PKCEOptionalForConfidential, from a registered confidential
// client.
func (h *AuthorizationHandler) validatePKCE(ctx context.Context, req *AuthorizationRequest) (errCode, errDescription string) {
	if req.CodeChallenge == "" {
		// OAuth 2.1 mandates PKCE for all clients, and that is the
		// default. PKCEOptionalForConfidential lets a registered
		// confidential client omit it, as OIDC Core allows; the code grant
		// then requires that client to authenticate.
		if h.PKCEPolicy == PKCEOptionalForConfidential && req.CodeChallengeMethod == "" && h.isConfidentialClient(ctx, req.ClientID) {
			return "", ""
		}
		return "invalid_request", "code_challenge is required (PKCE)"
	}
	if req.CodeChallengeMethod == "" {
		// RFC 7636 §4.3 defaults to "plain" when omitted. We require
		// the method to be sent explicitly so the client's intent is
		// unambiguous on the wire — and so a misconfigured client
		// doesn't accidentally pick the weaker method.
		return "invalid_request", "code_challenge_method is required"
	}
	switch req.CodeChallengeMethod {
	case core.CodeChallengeMethodS256:
		// OAuth 2.1 §7.5 mandated default; always accepted. The challenge
		// is a base64url SHA-256, so exactly 43 characters (RFC 7636 §4.2).
		if !s256Challenge.MatchString(req.CodeChallenge) {
			return "invalid_request", "code_challenge is not a base64url SHA-256 (43 characters)"
		}
	case core.CodeChallengeMethodPlain:
		if !pkceVerifierShape.MatchString(req.CodeChallenge) {
			return "invalid_request", "code_challenge must be 43 to 128 unreserved characters"
		}
		if !h.AllowPlainPKCE {
			return "invalid_request", "only S256 PKCE is supported (set OneAuthConfig.AllowPlainPKCE to permit plain for OAuth 2.0 fleets)"
		}
		h.allowPlainPKCEWarning.Do(func() {
			log.Printf("apiauth.AuthorizationHandler: LEGACY OAuth 2.0 PATH — code_challenge_method=plain accepted. " +
				"OAuth 2.1 §7.5 retired plain; the challenge equals the verifier, so any leaked authorization " +
				"request equals a leaked verifier. Disable by leaving OneAuthConfig.AllowPlainPKCE false.")
		})
	default:
		return "invalid_request", fmt.Sprintf("unsupported code_challenge_method=%q", req.CodeChallengeMethod)
	}
	return "", ""
}

// s256Challenge is a base64url-encoded SHA-256 without padding (RFC 7636
// §4.2), and pkceVerifierShape is RFC 7636 §4.1's code_verifier, which a
// plain challenge equals.
var (
	s256Challenge     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pkceVerifierShape = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// IssueCode mints + persists a fresh authorization code bound to the
// supplied (request, subject) tuple. The caller (the consent
// verification handler) calls this on Approve. Returns the code on
// success.
func (h *AuthorizationHandler) IssueCode(ctx context.Context, req *AuthorizationRequest, subject string, grantedScopes []string) (string, error) {
	// A pushed reference is spent by the approval that produces a code
	// (RFC 9126 §4), not when it is first read: the consent screen renders
	// on GET and approves on POST, and a reload in between is ordinary.
	// Spending it before minting makes the consume the single-use gate, so
	// of two approvals racing on one reference only one gets a code.
	if req.RequestURI != "" && h.PushedStore != nil {
		resp, err := h.PushedStore.ConsumePushedAuthorizationRequest(ctx, &core.ConsumePushedAuthorizationRequestRequest{RequestURI: req.RequestURI})
		if err != nil {
			return "", fmt.Errorf("consume request_uri: %w", err)
		}
		if !resp.Consumed {
			return "", errors.New("request_uri has already been used")
		}
	}

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
		Nonce:               req.Nonce,
		IDTokenClaims:       req.IDTokenClaims,
		UserinfoClaims:      req.UserinfoClaims,
		AuthTime:            req.AuthTime,
		ACR:                 req.ACR,
		AMR:                 req.AMR,
		Resources:           req.Resources,
		IssuedAt:            now,
		ExpiresAt:           now.Add(expiry),
	}
	if _, err := h.Store.CreateAuthorizationCode(ctx, &core.CreateAuthorizationCodeRequest{Code: entry}); err != nil {
		return "", err
	}

	return code, nil
}

// SuccessResponse builds the RFC 6749 §4.1.2 success response: code,
// state when the request had one, and iss under EmitIssParameter (RFC
// 9207), after RedirectOverride. Its Mode is the request's response mode.
func (h *AuthorizationHandler) SuccessResponse(req *AuthorizationRequest, code string) *AuthorizationResponse {
	return h.newResponse(req, url.Values{"code": {code}})
}

// SuccessRedirect composes the RFC 6749 §4.1.2 success redirect URL:
//
//	<redirect_uri>?code=<code>[&state=<state>][&iss=<iss>]
//
// The code goes in the fragment instead for response_mode=fragment. A
// form_post request has no redirect URL, so SuccessRedirect returns an
// error for one; use SuccessResponse.
func (h *AuthorizationHandler) SuccessRedirect(req *AuthorizationRequest, code string) (string, error) {
	return h.SuccessResponse(req, code).RedirectURL()
}

// ErrorResponse builds the RFC 6749 §4.1.2.1 error response: error,
// error_description when given, state and iss, in the request's response
// mode. That is the default for its response type when the request's own
// response_mode was the problem.
func (h *AuthorizationHandler) ErrorResponse(req *AuthorizationRequest, errCode, errDescription string) *AuthorizationResponse {
	values := url.Values{"error": {errCode}}
	if errDescription != "" {
		values.Set("error_description", core.OAuthErrorDescription(errDescription))
	}
	return h.newResponse(req, values)
}

// ErrorRedirect composes the RFC 6749 §4.1.2.1 error redirect URL:
//
//	<redirect_uri>?error=<code>[&error_description=...][&state=<state>][&iss=<iss>]
//
// The parameters go in the fragment for the implicit types or
// response_mode=fragment. Like SuccessRedirect it returns an error for a
// form_post request; use ErrorResponse.
func (h *AuthorizationHandler) ErrorRedirect(req *AuthorizationRequest, errCode, errDescription string) (string, error) {
	return h.ErrorResponse(req, errCode, errDescription).RedirectURL()
}

// isConfidentialClient reports whether clientID is registered in AppStore
// with a confidential token_endpoint_auth_method. With no AppStore, or a
// lookup that fails, it reports false, so PKCE stays required.
func (h *AuthorizationHandler) isConfidentialClient(ctx context.Context, clientID string) bool {
	if h.AppStore == nil || clientID == "" {
		return false
	}
	resp, err := h.AppStore.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	if err != nil || resp == nil || resp.App == nil {
		return false
	}
	return isConfidentialAuthMethod(resp.App.TokenEndpointAuthMethod)
}

func (h *AuthorizationHandler) validateRedirectURI(ctx context.Context, clientID, redirectURI string) error {
	if h.RedirectURIValidator != nil {
		return h.RedirectURIValidator(ctx, clientID, redirectURI)
	}
	if h.AppStore == nil {
		if h.AllowAnyRedirectURI {
			return nil
		}
		return newAuthorizeError("no client registry is configured to check redirect_uri against")
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
		if RedirectURIMatches(allowed, redirectURI) {
			return nil
		}
	}
	return errInvalidClientOrRedirect
}

// RedirectURIMatches reports whether a redirect_uri sent on an
// authorization request matches one the client registered. Matching is
// exact string comparison (RFC 6749 §3.1.2.2), with one exception from
// RFC 8252 §7.3: for an http redirect on a loopback host the port is
// ignored, because a native app binds an ephemeral port per login and
// cannot know it at registration. Scheme, host, path and query must
// still match exactly, and the requested URI must carry no userinfo or
// fragment.
//
// The loopback hosts are 127.0.0.1, [::1] and localhost. §7.3 requires
// the relaxation for the IP literals; localhost is included because
// §8.3 only discourages it and common native clients (oneauth's own
// LoginWithBrowser among them) send it. The host itself is never
// relaxed, so a client registered on 127.0.0.1 cannot be redirected to
// localhost or the reverse.
//
// Exported so deployments supplying AuthorizationHandler.RedirectURIValidator
// can apply the same rule to their own registry.
func RedirectURIMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	reg, err := url.Parse(registered)
	if err != nil {
		return false
	}
	req, err := url.Parse(requested)
	if err != nil {
		return false
	}
	if reg.Scheme != "http" || req.Scheme != "http" || !isLoopbackHost(req.Hostname()) {
		return false
	}
	if req.User != nil || reg.User != nil || req.Fragment != "" || req.Opaque != "" {
		return false
	}
	return strings.EqualFold(reg.Hostname(), req.Hostname()) &&
		reg.EscapedPath() == req.EscapedPath() &&
		reg.RawQuery == req.RawQuery
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
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
// existing params, and sets the fragment to "_=_". Returns the encoded URL.
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
	// RFC 9700 §4.1.3: a fragment of our own stops the browser carrying
	// one from the authorization request over to the client.
	u.Fragment = "_=_"
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

// parsePromptAndMaxAge fills req.Prompt and req.MaxAge from the OIDC Core
// §3.1.2.1 parameters. It refuses "none" combined with another prompt
// value, which the spec calls an error, and a max_age that isn't a
// non-negative integer.
func parsePromptAndMaxAge(req *AuthorizationRequest, values url.Values) (errCode, errDescription string) {
	req.Prompt = strings.Fields(values.Get("prompt"))
	if slices.Contains(req.Prompt, "none") && len(req.Prompt) > 1 {
		return "invalid_request", "prompt=none cannot be combined with other prompt values"
	}
	if raw := strings.TrimSpace(values.Get("max_age")); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			return "invalid_request", "max_age must be a non-negative integer"
		}
		req.MaxAge = &n
	}
	return "", ""
}

// parseClaimsParam reads the OIDC Core §5.5 `claims` parameter into
// req.Claims, req.IDTokenClaims and req.UserinfoClaims. The value must be
// a JSON object, and its "id_token" and "userinfo" members, when present,
// objects whose members are null or objects (§5.5.1). Other members are
// ignored. oneauth treats every requested claim as voluntary: it returns
// the ones the user has, and never refuses a request over a missing
// "essential" claim, which §5.5.1 allows.
func parseClaimsParam(req *AuthorizationRequest, values url.Values) (errCode, errDescription string) {
	raw := strings.TrimSpace(values.Get("claims"))
	if raw == "" {
		return "", ""
	}
	const bad = "claims must be a JSON object whose id_token and userinfo members map claim names to null or an object (OIDC Core §5.5)"
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil || top == nil {
		return "invalid_request", bad
	}
	names := func(member string) ([]string, bool) {
		m, ok := top[member]
		if !ok || string(m) == "null" {
			return nil, true
		}
		var requests map[string]json.RawMessage
		if err := json.Unmarshal(m, &requests); err != nil || requests == nil {
			return nil, false
		}
		out := make([]string, 0, len(requests))
		for name, spec := range requests {
			if t := strings.TrimSpace(string(spec)); t != "null" && !strings.HasPrefix(t, "{") {
				return nil, false
			}
			out = append(out, name)
		}
		slices.Sort(out)
		return out, true
	}
	idToken, ok1 := names("id_token")
	userinfo, ok2 := names("userinfo")
	if !ok1 || !ok2 {
		return "invalid_request", bad
	}
	req.Claims, req.IDTokenClaims, req.UserinfoClaims = raw, idToken, userinfo
	return "", ""
}
