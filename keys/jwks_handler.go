package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/panyam/oneauth/utils"
)

// JWKSHandler serves a JWKS (JSON Web Key Set) endpoint at /.well-known/jwks.json.
// Only asymmetric keys (RS256/ES256) are included — HS256 secrets are never exposed.
type JWKSHandler struct {
	KeyStore    KeyStorage // needs ListKeyIDs() and GetKey()
	KidStore    *KidStore  // optional: serves previous keys during grace period
	CacheMaxAge int        // Cache-Control max-age in seconds (default: 3600)
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIDs, err := h.KeyStore.ListKeyIDs()
	if err != nil {
		http.Error(w, `{"error":"failed to list keys"}`, http.StatusInternalServerError)
		return
	}

	var keys []utils.JWK
	for _, clientID := range clientIDs {
		rec, err := h.KeyStore.GetKey(clientID)
		if err != nil {
			log.Printf("jwks: failed to get key for %s: %v", clientID, err)
			continue
		}
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
		http.Error(w, `{"error":"failed to marshal JWKS"}`, http.StatusInternalServerError)
		return
	}

	// ETag based on SHA-256 of the response body — changes when key set changes
	hash := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(hash[:16]) + `"`

	// Support conditional requests (If-None-Match)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(body)
}
