package apiauth

import (
	"encoding/json"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/tracing"
)

// IntrospectionHandler implements OAuth 2.0 Token Introspection (RFC 7662).
// Resource servers POST tokens to this endpoint to check validity, as an
// alternative to local JWT validation via JWKS.
//
// The handler is a thin HTTP wrapper over TokenIntrospector (core logic)
// and ClientAuthenticator (caller verification).
//
// See: https://www.rfc-editor.org/rfc/rfc7662
type IntrospectionHandler struct {
	// Introspector performs the actual token introspection (transport-independent).
	Introspector TokenIntrospector

	// Authenticator verifies the caller's client credentials.
	Authenticator ClientAuthenticator

	// AcceptedAudiences are the URLs the AS will accept as the
	// `aud` claim of a private_key_jwt / client_secret_jwt client
	// assertion (OIDC Core §9). Typically the introspection endpoint
	// URL plus the AS issuer URL. When empty the URL of the request
	// is used as a fallback, which works for single-host deployments
	// but breaks behind proxies that rewrite the path — populate
	// explicitly in production.
	AcceptedAudiences []string

	// TracerProvider opts the introspection endpoint into SEP-414
	// tracing. When set, ServeHTTP extracts an inbound `traceparent`
	// header and emits an `oneauth.introspect` span carrying the
	// resulting `token_active` boolean. Nil keeps tracing on the
	// no-op fast path.
	TracerProvider trace.TracerProvider
}

// Construction of an IntrospectionHandler now happens via
// OneAuth.IntrospectionHTTPHandler() — the legacy APIAuth-based
// constructor was removed in #298.

func joinScopes(scopes []string) string {
	s := ""
	for i, sc := range scopes {
		if i > 0 {
			s += " "
		}
		s += sc
	}
	return s
}

// ServeHTTP handles POST /oauth/introspect per RFC 7662.
func (h *IntrospectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracing.Tracer(h.TracerProvider, tracing.InstrumentationName).
		Start(tracing.Extract(r), "oneauth.introspect", trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	r = r.WithContext(ctx)

	if r.Method != http.MethodPost {
		span.SetStatus(codes.Error, "method not allowed")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form before extracting credentials — client_secret_post
	// and private_key_jwt both live in the form body.
	if err := r.ParseForm(); err != nil {
		h.jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}

	creds, ok := extractClientCredentials(r, nil)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	creds.Audiences = h.AcceptedAudiences
	if len(creds.Audiences) == 0 {
		creds.Audiences = []string{derivedAudience(r)}
	}
	if _, err := h.Authenticator.AuthenticateClient(r.Context(), creds); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		h.jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": "token parameter is required"})
		return
	}

	// Delegate to transport-independent introspector
	introspectResp, err := h.Introspector.Introspect(r.Context(), &IntrospectRequest{Token: token})
	if err != nil || introspectResp == nil || !introspectResp.Result.Active {
		// RFC 7662: invalid tokens get {"active": false}, never an error
		span.SetAttributes(attribute.Bool("oauth.token_active", false))
		h.jsonResponse(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	result := introspectResp.Result
	span.SetAttributes(attribute.Bool("oauth.token_active", true))

	// Build response from IntrospectionResult
	resp := map[string]any{
		"active":     true,
		"sub":        result.Sub,
		"token_type": result.TokenType,
	}
	if result.Scope != "" {
		resp["scope"] = result.Scope
	}
	if result.Iss != "" {
		resp["iss"] = result.Iss
	}
	if result.Exp != 0 {
		resp["exp"] = result.Exp
	}
	if result.Iat != 0 {
		resp["iat"] = result.Iat
	}
	if result.Aud != nil {
		resp["aud"] = result.Aud
	}
	if result.Jti != "" {
		resp["jti"] = result.Jti
	}
	if result.ClientID != "" {
		resp["client_id"] = result.ClientID
	}

	// Include authorization_details if present (RFC 9396 §9.1)
	rawClaims := parseRawJWTClaims(token)
	if ad, ok := rawClaims["authorization_details"]; ok {
		resp["authorization_details"] = ad
	}

	h.jsonResponse(w, http.StatusOK, resp)
}

// jsonResponse writes a JSON response with the given status code.
func (h *IntrospectionHandler) jsonResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
