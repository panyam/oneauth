package apiauth

// Hooks provides lifecycle callbacks for OneAuth operations.
// Grouped by concern — each implementation receives only its relevant group.
// All callbacks are optional — nil callbacks are no-ops.
//
// Configure all hooks in one place on OneAuth.Hooks. Callers set only
// what they need:
//
//	oa := NewOneAuth(OneAuthConfig{
//	    Hooks: Hooks{
//	        Token: TokenHooks{
//	            OnRevoked: func(token, hint string) { audit.Log("revoked", token) },
//	        },
//	    },
//	})
//
// See: https://github.com/panyam/oneauth/issues/110
type Hooks struct {
	Token    TokenHooks
	Auth     AuthHooks
	Client   ClientHooks
	Security SecurityHooks
}

// TokenHooks fires on token lifecycle events.
type TokenHooks struct {
	// OnIssued fires after an access token is successfully created.
	// subject is the token's sub claim, grantType is the OAuth grant used.
	OnIssued func(subject, grantType string)

	// OnRefreshed fires after a refresh token is rotated and a new access token issued.
	OnRefreshed func(subject string)

	// OnRevoked fires after a token is successfully revoked.
	// hint is the token_type_hint ("access_token", "refresh_token", or "").
	OnRevoked func(token, hint string)
}

// AuthHooks fires on authentication events.
type AuthHooks struct {
	// OnLoginSuccess fires after a user successfully authenticates
	// (password grant, auth code exchange).
	OnLoginSuccess func(userID string)

	// OnLoginFailure fires after a failed authentication attempt.
	OnLoginFailure func(username string, err error)

	// OnScopeStepUp fires when additional scopes are requested and granted.
	// from is the original scope set, to is the expanded set.
	OnScopeStepUp func(subject string, from, to []string)
}

// ClientHooks fires on client management events.
type ClientHooks struct {
	// OnRegistered fires after a new client is registered (DCR or proprietary).
	// method is "dcr" or "register".
	OnRegistered func(clientID, method string)

	// OnDeleted fires after a client is deleted.
	OnDeleted func(clientID string)

	// OnKeyRotated fires after a client's signing key is rotated.
	OnKeyRotated func(clientID string)
}

// SecurityHooks fires on security-relevant events.
// Use these for alerting, audit logging, and intrusion detection.
type SecurityHooks struct {
	// OnTokenRejected fires when a token fails validation.
	// reason describes why (expired, bad signature, revoked, etc.).
	OnTokenRejected func(reason string)

	// OnBlacklistHit fires when a revoked token is presented.
	// This indicates token reuse after revocation — potential theft.
	OnBlacklistHit func(jti string)

	// OnAlgorithmMismatch fires when a token's alg header doesn't match
	// the stored key's algorithm. This is the CVE-2015-9235 attack vector.
	OnAlgorithmMismatch func(expected, got string)
}

// --- Hook helpers (fire if non-nil) ---

func (h *TokenHooks) fireOnIssued(subject, grantType string) {
	if h != nil && h.OnIssued != nil {
		h.OnIssued(subject, grantType)
	}
}

func (h *TokenHooks) fireOnRevoked(token, hint string) {
	if h != nil && h.OnRevoked != nil {
		h.OnRevoked(token, hint)
	}
}

func (h *SecurityHooks) fireOnTokenRejected(reason string) {
	if h != nil && h.OnTokenRejected != nil {
		h.OnTokenRejected(reason)
	}
}

func (h *SecurityHooks) fireOnBlacklistHit(jti string) {
	if h != nil && h.OnBlacklistHit != nil {
		h.OnBlacklistHit(jti)
	}
}

func (h *SecurityHooks) fireOnAlgorithmMismatch(expected, got string) {
	if h != nil && h.OnAlgorithmMismatch != nil {
		h.OnAlgorithmMismatch(expected, got)
	}
}
