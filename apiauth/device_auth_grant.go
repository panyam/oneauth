package apiauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/panyam/oneauth/core"
)

// DeviceCodeGrantType is the OAuth grant type URI for the RFC 8628 device
// authorization grant. The device polls the token endpoint with this
// grant_type and a device_code obtained from /device/authorize.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.4
const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// Spec defaults for RFC 8628. Callers tune via APIAuth fields.
const (
	// DefaultDeviceAuthorizationExpiry is the RFC 8628 §3.4 recommended
	// 15-minute deadline for a user to complete the verification flow.
	DefaultDeviceAuthorizationExpiry = 15 * time.Minute

	// DefaultDeviceAuthorizationInterval is the RFC 8628 §3.5 default
	// polling interval; clients MUST wait at least this long between
	// token requests.
	DefaultDeviceAuthorizationInterval = 5

	// deviceUserCodeCharset is the RFC 8628 §6.1 recommended charset:
	// 20 characters chosen for legibility on cramped device displays and
	// resistance to transcription error. No 0/O, no 1/I/L, no U/Y/A.
	deviceUserCodeCharset = "BCDEFGHJKLMNPQRSTVWXZ23456789"

	// deviceUserCodeLength controls how many characters the user types.
	// 8 chars at 29 symbols ≈ 39 bits of entropy — plenty given the
	// 15-minute window and rate-limited polling.
	deviceUserCodeLength = 8

	// deviceCodeBytes is the entropy budget for the high-entropy code
	// the device polls with. 256 bits ⇒ unguessable in any practical
	// attacker timeframe.
	deviceCodeBytes = 32
)

// DeviceAuthorizationHandler serves POST /device/authorize per RFC 8628
// §3.1 / §3.2. The handler validates the client, mints fresh
// device_code + user_code, persists a pending authorization, and returns
// the polling parameters the device needs.
//
// The handler authenticates the client via the same ClientAuthenticator
// the token endpoint uses (when set) so public clients (`token_endpoint_
// auth_method=none`) and confidential clients are handled uniformly.
type DeviceAuthorizationHandler struct {
	// Store persists the device authorization. Required.
	Store core.DeviceAuthorizationStore

	// VerificationURI is the absolute URL the device displays to the
	// user. RFC 8628 §3.2 makes this REQUIRED on the response. Production
	// deployments point it at the AS's HTML user-code form (a follow-up
	// PR ships this UI); tests can point it anywhere — the field is
	// echoed verbatim.
	VerificationURI string

	// VerificationURICompleteTemplate, when non-empty, is appended with
	// the user_code substituted into "%s" to produce the
	// verification_uri_complete field (RFC 8628 §3.3.1). The convenience
	// URL lets the device generate a QR code that pre-fills the form.
	// Example: "https://auth.example.com/device?user_code=%s".
	VerificationURICompleteTemplate string

	// Expiry overrides the default 15-minute authorization window.
	Expiry time.Duration

	// Interval overrides the default 5-second polling interval.
	Interval int

	// ClientAuthenticator, when non-nil, authenticates the calling client
	// before minting codes. When nil the handler accepts any client_id —
	// suitable for public-client-only deployments and tests, NOT for
	// production with confidential clients.
	ClientAuthenticator ClientAuthenticator
}

// ServeHTTP implements the RFC 8628 §3.1 device authorization request
// endpoint. Body MUST be application/x-www-form-urlencoded. Form fields:
//
//   - client_id (REQUIRED for public clients; confidential clients also
//     send credentials, picked up by the ClientAuthenticator)
//   - scope (OPTIONAL)
//   - audience (OPTIONAL, RFC 8707 extension)
//
// On success returns 200 with the JSON shape defined by §3.2.
func (h *DeviceAuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	clientID := r.FormValue("client_id")
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client_id is required")
		return
	}
	if h.ClientAuthenticator != nil {
		resp, err := h.ClientAuthenticator.AuthenticateClient(r.Context(), &AuthenticateClientRequest{
			ClientID:            clientID,
			ClientSecret:        r.FormValue("client_secret"),
			ClientAssertionType: r.FormValue("client_assertion_type"),
			ClientAssertion:     r.FormValue("client_assertion"),
		})
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}
		if resp != nil && resp.ClientID != "" {
			clientID = resp.ClientID
		}
	}
	if h.Store == nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "device authorization store not configured")
		return
	}

	deviceCode, err := generateDeviceCode()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "generate device_code: "+err.Error())
		return
	}
	userCode, err := generateUserCode()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "generate user_code: "+err.Error())
		return
	}

	now := time.Now()
	expiry := h.Expiry
	if expiry <= 0 {
		expiry = DefaultDeviceAuthorizationExpiry
	}
	interval := h.Interval
	if interval <= 0 {
		interval = DefaultDeviceAuthorizationInterval
	}
	scopes := core.ParseScopes(r.FormValue("scope"))
	auth := &core.DeviceAuthorization{
		DeviceCode:        deviceCode,
		UserCode:          userCode,
		ClientID:          clientID,
		Scopes:            scopes,
		RequestedAudience: r.FormValue("audience"),
		Status:            core.DeviceAuthorizationStatusPending,
		CreatedAt:         now,
		ExpiresAt:         now.Add(expiry),
		IntervalSeconds:   interval,
	}
	if _, err := h.Store.CreateDeviceAuthorization(r.Context(), &core.CreateDeviceAuthorizationRequest{Authorization: auth}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "persist device authorization: "+err.Error())
		return
	}

	resp := deviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        formatUserCodeForDisplay(userCode),
		VerificationURI: h.VerificationURI,
		ExpiresIn:       int64(expiry.Seconds()),
		Interval:        interval,
	}
	if h.VerificationURICompleteTemplate != "" {
		resp.VerificationURIComplete = fmt.Sprintf(h.VerificationURICompleteTemplate, resp.UserCode)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(&resp)
}

// deviceAuthorizationResponse is the RFC 8628 §3.2 wire shape.
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

// generateDeviceCode returns the 256-bit hex-encoded device_code.
func generateDeviceCode() (string, error) {
	b := make([]byte, deviceCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateUserCode returns a fresh user_code drawn from the
// RFC 8628 §6.1 charset.
func generateUserCode() (string, error) {
	b := make([]byte, deviceUserCodeLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, deviceUserCodeLength)
	for i, v := range b {
		out[i] = deviceUserCodeCharset[int(v)%len(deviceUserCodeCharset)]
	}
	return string(out), nil
}

// formatUserCodeForDisplay inserts a separator for legibility — XXXX-XXXX
// reads more cleanly on small screens than XXXXXXXX. The store
// normalizes back to the canonical no-dash form before lookup, so the
// device may render and the user may type either.
func formatUserCodeForDisplay(raw string) string {
	if len(raw) != deviceUserCodeLength {
		return raw
	}
	return raw[:4] + "-" + raw[4:]
}

// isConfidentialAuthMethod reports whether a registered client's
// `token_endpoint_auth_method` mandates credentials on every token
// endpoint call. RFC 6749 §2.3 + RFC 8628 §3.4: any method other than
// `none` requires authentication. Empty (no method advertised) defaults
// to `client_secret_basic` per OIDC Core §9 — also confidential.
func isConfidentialAuthMethod(method string) bool {
	return method != "none"
}

// writeOAuthError is the canonical RFC 6749 §5.2 error response. Used by
// both the /device/authorize endpoint and the token endpoint's device
// grant branch.
func writeOAuthError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(core.TokenError{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// handleDeviceCodeGrant is the token endpoint branch for
// grant_type=urn:ietf:params:oauth:grant-type:device_code. It maps the
// store's status + clock to the RFC 8628 §3.5 error taxonomy:
//
//	pending → 400 authorization_pending
//	too-fast → 400 slow_down (and bumps the interval by 5s)
//	denied → 400 access_denied
//	expired (ExpiresAt past) → 400 expired_token
//	unknown device_code → 400 invalid_grant
//	approved → 200 access token + (optional) refresh token
//
// A successful exchange deletes the device authorization so a leaked
// device_code cannot be replayed for a second access token.
func (a *APIAuth) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request, req *core.TokenRequest) {
	if a.DeviceAuthStore == nil {
		a.errorResponse(w, "unsupported_grant_type", "device authorization grant not enabled", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.DeviceCode) == "" {
		a.errorResponse(w, "invalid_request", "device_code is required", http.StatusBadRequest)
		return
	}
	getResp, err := a.DeviceAuthStore.GetByDeviceCode(r.Context(), &core.GetByDeviceCodeRequest{DeviceCode: req.DeviceCode})
	if err != nil {
		a.errorResponse(w, "invalid_grant", "device_code not recognized", http.StatusBadRequest)
		return
	}
	auth := getResp.Authorization

	// Confidential clients MUST authenticate (issue 266). When the
	// registered client's `token_endpoint_auth_method` is anything other
	// than `none`, the redemption request MUST present credentials and
	// pass the same ClientAuthenticator the rest of the token endpoint
	// uses. The authenticated client_id then drives the §3.4 binding
	// check, so a stolen device_code with mismatched (or missing) creds
	// cannot redeem even when the form `client_id` happens to match.
	effectiveClientID := req.ClientID
	if a.AppStore != nil && auth.ClientID != "" {
		appResp, lookupErr := a.AppStore.GetApp(r.Context(), &core.GetAppRequest{ClientID: auth.ClientID})
		switch {
		case lookupErr == nil && appResp != nil && appResp.App != nil && isConfidentialAuthMethod(appResp.App.TokenEndpointAuthMethod):
			authedID, authErr := a.authenticateTokenEndpointClient(r, req)
			if authErr != nil {
				a.errorResponse(w, "invalid_client", "client authentication required for confidential device client", http.StatusUnauthorized)
				return
			}
			effectiveClientID = authedID
		case lookupErr == nil && appResp != nil && appResp.App != nil:
			// Public client (auth_method=none) — form client_id is the
			// identifier, no authentication step.
		default:
			// Lookup failure — fall back to the form client_id (status
			// quo). A noisy registration store shouldn't block legitimate
			// polling; the §3.4 binding check below still applies.
		}
	}

	if auth.ClientID != "" && auth.ClientID != effectiveClientID {
		// Per RFC 8628 §3.4 the same client_id that obtained the
		// device_code MUST be used to redeem it. We REQUIRE a matching
		// client_id whenever the stored authorization has one bound —
		// an empty req.ClientID against a bound auth.ClientID is a
		// binding bypass attempt (a thief who stole the device_code
		// just omits client_id to skip the check) and rejects with
		// invalid_grant just like any other mismatch.
		a.errorResponse(w, "invalid_grant", "device_code was not issued to this client", http.StatusBadRequest)
		return
	}
	now := time.Now()
	if auth.IsExpired(now) {
		a.errorResponse(w, "expired_token", "device_code expired", http.StatusBadRequest)
		return
	}

	switch auth.Status {
	case core.DeviceAuthorizationStatusDenied:
		a.errorResponse(w, "access_denied", "user denied the authorization", http.StatusBadRequest)
		return
	case core.DeviceAuthorizationStatusPending:
		slow := !auth.LastPolledAt.IsZero() && now.Sub(auth.LastPolledAt) < time.Duration(auth.IntervalSeconds)*time.Second
		_, _ = a.DeviceAuthStore.UpdatePollingState(r.Context(), &core.UpdatePollingStateRequest{
			DeviceCode: auth.DeviceCode,
			PolledAt:   now,
			SlowDown:   slow,
		})
		if slow {
			a.errorResponse(w, "slow_down", "polling too quickly", http.StatusBadRequest)
			return
		}
		a.errorResponse(w, "authorization_pending", "user has not yet completed the authorization", http.StatusBadRequest)
		return
	case core.DeviceAuthorizationStatusApproved:
		// fall through to issuance
	default:
		a.errorResponse(w, "invalid_grant", "device authorization in unknown state", http.StatusBadRequest)
		return
	}

	subject := auth.ApprovedSubject
	if subject == "" {
		a.errorResponse(w, "invalid_grant", "approved authorization is missing subject", http.StatusBadRequest)
		return
	}

	issuer, err := a.Issuer().CreateAccessToken(r.Context(), &CreateAccessTokenRequest{
		Subject: subject,
		Scopes:  auth.Scopes,
	})
	if err != nil {
		a.errorResponse(w, "server_error", "create access token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var refreshToken string
	if a.RefreshTokenStore != nil {
		createResp, rtErr := a.RefreshTokenStore.CreateRefreshToken(r.Context(), &core.CreateRefreshTokenRequest{
			Subject:  subject,
			ClientID: auth.ClientID,
			Scopes:   auth.Scopes,
		})
		if rtErr == nil && createResp != nil && createResp.Token != nil {
			refreshToken = createResp.Token.Token
		}
	}

	// Consume the authorization so a stolen device_code cannot be
	// replayed for a second access token. Errors here are non-fatal;
	// the access token has already been minted.
	_, _ = a.DeviceAuthStore.DeleteDeviceAuthorization(r.Context(), &core.DeleteDeviceAuthorizationRequest{DeviceCode: auth.DeviceCode})

	a.tokenResponse(w, issuer.Token, issuer.ExpiresIn, refreshToken, auth.Scopes, nil)
}

// ApproveDeviceAuthorization is the programmatic approval entry point.
// The follow-up UI PR wires this behind a localauth-protected HTML form;
// tests and in-process consumers call it directly.
//
// userCode is normalized case-insensitively. grantedScopes overrides the
// scope set the device requested (consent UI may narrow the scope); pass
// nil to keep the original set.
func (a *APIAuth) ApproveDeviceAuthorization(r *http.Request, userCode, subject string, grantedScopes []string) error {
	if a.DeviceAuthStore == nil {
		return fmt.Errorf("device authorization store not configured")
	}
	_, err := a.DeviceAuthStore.ApproveDeviceAuthorization(r.Context(), &core.ApproveDeviceAuthorizationRequest{
		UserCode:        userCode,
		ApprovedSubject: subject,
		GrantedScopes:   grantedScopes,
	})
	return err
}

// DenyDeviceAuthorization is the programmatic deny entry point. Mirrors
// ApproveDeviceAuthorization's signature for the future UI's symmetry.
func (a *APIAuth) DenyDeviceAuthorization(r *http.Request, userCode string) error {
	if a.DeviceAuthStore == nil {
		return fmt.Errorf("device authorization store not configured")
	}
	_, err := a.DeviceAuthStore.DenyDeviceAuthorization(r.Context(), &core.DenyDeviceAuthorizationRequest{UserCode: userCode})
	return err
}
