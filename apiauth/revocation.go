package apiauth

import (
	"encoding/json"
	"net/http"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/tracing"
)

// RevocationHandler implements OAuth 2.0 Token Revocation (RFC 7009).
// It is a thin HTTP wrapper over TokenRevoker (core logic) and
// ClientAuthenticator (caller verification).
//
// See: https://www.rfc-editor.org/rfc/rfc7009
type RevocationHandler struct {
	// Revoker performs the actual token revocation (transport-independent).
	Revoker TokenRevoker

	// Authenticator verifies the caller's client credentials.
	Authenticator ClientAuthenticator

	// AcceptedAudiences are the URLs the AS will accept as the
	// `aud` claim of a private_key_jwt / client_secret_jwt client
	// assertion (OIDC Core §9). When empty the URL of the request
	// is used as a fallback.
	AcceptedAudiences []string

	// TracerProvider opts the revocation endpoint into SEP-414 tracing.
	// When set, ServeHTTP extracts an inbound `traceparent` header and
	// emits an `oneauth.revoke` span. Nil keeps the handler on the
	// no-op fast path.
	TracerProvider trace.TracerProvider
}

// NewRevocationHandler creates a RevocationHandler from an APIAuth and
// a client KeyLookup. Bridge constructor for existing code. The new
// handler inherits the APIAuth's TracerProvider so spans share one
// trace across /token and /revoke.
func NewRevocationHandler(auth *APIAuth, clientKeyStore keys.KeyLookup) *RevocationHandler {
	revoker := NewTokenRevoker(TokenRevokerConfig{
		Blacklist:    auth.Blacklist,
		RefreshStore: auth.RefreshTokenStore,
		// Inherit auth.TokenHooks so OnRevoked / OnTokenRevoked fire from
		// /oauth/revoke just as they do from /api/logout. Without this,
		// the OIDC Back-Channel Logout dispatcher would miss revocations
		// triggered through the RFC 7009 endpoint.
		Hooks: auth.TokenHooks,
	})
	return &RevocationHandler{
		Revoker:        revoker,
		Authenticator:  NewClientAuthenticator(clientKeyStore),
		TracerProvider: auth.TracerProvider,
	}
}

// ServeHTTP handles POST /oauth/revoke per RFC 7009.
func (h *RevocationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracing.Tracer(h.TracerProvider, tracing.InstrumentationName).
		Start(tracing.Extract(r), "oneauth.revoke", trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	r = r.WithContext(ctx)

	if r.Method != http.MethodPost {
		span.SetStatus(codes.Error, "method not allowed")
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form body
	if err := r.ParseForm(); err != nil {
		h.okResponse(w)
		return
	}

	creds, ok := extractClientCredentials(r, nil)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="revocation"`)
		h.errorResponse(w, "invalid_client", "Authentication required", http.StatusUnauthorized)
		return
	}
	creds.Audiences = h.AcceptedAudiences
	if len(creds.Audiences) == 0 {
		creds.Audiences = []string{derivedAudience(r)}
	}
	if _, err := h.Authenticator.AuthenticateClient(r.Context(), creds); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="revocation"`)
		h.errorResponse(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Extract token and hint
	token := r.FormValue("token")
	if token == "" {
		h.okResponse(w)
		return
	}
	hint := r.FormValue("token_type_hint")

	// Delegate to transport-independent revoker
	h.Revoker.Revoke(r.Context(), &RevokeRequest{Token: token, TokenTypeHint: hint})

	// RFC 7009 §2.2: always 200 OK
	h.okResponse(w)
}

// okResponse sends 200 OK with no body (RFC 7009 §2.2).
func (h *RevocationHandler) okResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
}

// errorResponse sends a JSON error (only for auth failures).
func (h *RevocationHandler) errorResponse(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
