package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/tracing"
	"github.com/panyam/oneauth/utils"
)



// JWKSHandler serves a JWKS (JSON Web Key Set) endpoint at /.well-known/jwks.json.
// Only asymmetric keys (RS256/ES256) are included — HS256 secrets are never exposed.
type JWKSHandler struct {
	KeyStore    KeyStorage // needs ListKeyIDs() and GetKey()
	KidStore    *KidStore  // optional: serves previous keys during grace period
	CacheMaxAge int        // Cache-Control max-age in seconds (default: 3600)

	// TracerProvider opts the handler into SEP-414 (W3C Trace Context)
	// observability. When non-nil, every ServeHTTP call:
	//   - extracts an inbound `traceparent` header (silently dropping a
	//     malformed value per W3C §3.2.2.5), and
	//   - emits a single `oneauth.jwks.serve` span with the response status
	//     and the number of asymmetric keys returned.
	// Leaving this nil keeps the handler on the no-op fast path with no
	// allocation cost — same opt-in shape as mcpkit's
	// server.WithTracerProvider. See tests/keycloak/ and the SEP-414
	// trace chain in issue #254 for the cross-process context.
	TracerProvider trace.TracerProvider
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := tracing.Extract(r)
	ctx, span := tracing.Tracer(h.TracerProvider, tracing.InstrumentationName).
		Start(ctx, "oneauth.jwks.serve", trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()

	listResp, err := h.KeyStore.ListKeyIDs(ctx, &ListKeyIDsRequest{})
	if err != nil {
		span.SetStatus(codes.Error, "list keys failed")
		span.RecordError(err)
		http.Error(w, `{"error":"failed to list keys"}`, http.StatusInternalServerError)
		return
	}

	var keys []utils.JWK
	for _, clientID := range listResp.ClientIDs {
		getResp, err := h.KeyStore.GetKey(ctx, &GetKeyRequest{ClientID: clientID})
		if err != nil {
			log.Printf("jwks: failed to get key for %s: %v", clientID, err)
			continue
		}
		rec := getResp.Record
		if !utils.IsAsymmetricAlg(rec.Algorithm) {
			continue
		}
		pubKey, err := utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
		if err != nil {
			log.Printf("jwks: failed to decode verify key for %s: %v", clientID, err)
			continue
		}
		kid, err := utils.ComputeKid(pubKey, rec.Algorithm)
		if err != nil {
			log.Printf("jwks: failed to compute kid for %s: %v", clientID, err)
			continue
		}
		jwk, err := utils.PublicKeyToJWK(kid, rec.Algorithm, pubKey)
		if err != nil {
			log.Printf("jwks: failed to convert key for %s: %v", clientID, err)
			continue
		}
		keys = append(keys, jwk)
	}

	// Include previous asymmetric keys from KidStore (grace period entries)
	if h.KidStore != nil {
		kidsSeen := make(map[string]bool, len(keys))
		for _, k := range keys {
			kidsSeen[k.Kid] = true
		}
		h.KidStore.mu.RLock()
		for kid, rec := range h.KidStore.records {
			if rec.isExpired() || kidsSeen[kid] || !utils.IsAsymmetricAlg(rec.Algorithm) {
				continue
			}
			pubKey, err := utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
			if err != nil {
				continue
			}
			jwk, err := utils.PublicKeyToJWK(kid, rec.Algorithm, pubKey)
			if err != nil {
				continue
			}
			keys = append(keys, jwk)
		}
		h.KidStore.mu.RUnlock()
	}

	if keys == nil {
		keys = []utils.JWK{}
	}
	jwkSet := utils.JWKSet{Keys: keys}

	maxAge := h.CacheMaxAge
	if maxAge <= 0 {
		maxAge = 3600
	}

	// Marshal once for ETag computation and response
	body, err := json.Marshal(jwkSet)
	if err != nil {
		span.SetStatus(codes.Error, "marshal failed")
		span.RecordError(err)
		http.Error(w, `{"error":"failed to marshal JWKS"}`, http.StatusInternalServerError)
		return
	}

	span.SetAttributes(attribute.Int("jwks.keys_returned", len(keys)))

	// ETag based on SHA-256 of the response body — changes when key set changes
	hash := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(hash[:16]) + `"`

	// Support conditional requests (If-None-Match)
	if r.Header.Get("If-None-Match") == etag {
		span.SetAttributes(attribute.Int("http.response.status_code", http.StatusNotModified))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	span.SetAttributes(attribute.Int("http.response.status_code", http.StatusOK))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(body)
}
