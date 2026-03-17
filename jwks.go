package oneauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/panyam/oneauth/utils"
)

// JWKSHandler serves a JWKS (JSON Web Key Set) endpoint at /.well-known/jwks.json.
// Only asymmetric keys (RS256/ES256) are included — HS256 secrets are never exposed.
type JWKSHandler struct {
	KeyStore    WritableKeyStore // needs ListKeys()
	CacheMaxAge int              // Cache-Control max-age in seconds (default: 3600)
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIDs, err := h.KeyStore.ListKeys()
	if err != nil {
		http.Error(w, `{"error":"failed to list keys"}`, http.StatusInternalServerError)
		return
	}

	var keys []utils.JWK
	for _, clientID := range clientIDs {
		alg, err := h.KeyStore.GetExpectedAlg(clientID)
		if err != nil {
			log.Printf("jwks: failed to get algorithm for %s: %v", clientID, err)
			continue
		}
		if !utils.IsAsymmetricAlg(alg) {
			continue
		}
		rawKey, err := h.KeyStore.GetVerifyKey(clientID)
		if err != nil {
			log.Printf("jwks: failed to get verify key for %s: %v", clientID, err)
			continue
		}
		// Convert raw key material to crypto.PublicKey
		pubKey, err := utils.DecodeVerifyKey(rawKey, alg)
		if err != nil {
			log.Printf("jwks: failed to decode verify key for %s: %v", clientID, err)
			continue
		}
		jwk, err := utils.PublicKeyToJWK(clientID, alg, pubKey)
		if err != nil {
			log.Printf("jwks: failed to convert key for %s: %v", clientID, err)
			continue
		}
		keys = append(keys, jwk)
	}

	if keys == nil {
		keys = []utils.JWK{}
	}
	jwkSet := utils.JWKSet{Keys: keys}

	maxAge := h.CacheMaxAge
	if maxAge <= 0 {
		maxAge = 3600
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	json.NewEncoder(w).Encode(jwkSet)
}
