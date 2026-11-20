package main

import (
	"crypto"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// defaultKeyRotationGrace is jwt.key_rotation.grace_period when unset.
const defaultKeyRotationGrace = 24 * time.Hour

// signingKeyRotator serves POST /admin/signing-key/rotate (issue 507). It
// generates a key of the same algorithm, keeps the current public key in
// the kid store for the grace period, publishes the new public key under
// issuerClientID, and only then has the source sign with it. In that
// order, a token is never signed with a key the JWKS doesn't have yet.
type signingKeyRotator struct {
	auth     admin.AdminAuth
	source   *apiauth.RotatingSigningKey
	keyStore keys.KeyStorage
	kidStore keys.KidStorage
	grace    time.Duration
	generate func() (crypto.PrivateKey, []byte, error)
}

func (s *signingKeyRotator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.auth.Authenticate(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	out, err := s.rotate(r)
	if err != nil {
		log.Printf("signing key rotation: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *signingKeyRotator) rotate(r *http.Request) (map[string]string, error) {
	ctx := r.Context()
	current, alg := s.source.CurrentSigningKey()
	oldPub := current.(crypto.Signer).Public()
	oldKid, err := utils.ComputeKid(oldPub, alg)
	if err != nil {
		return nil, fmt.Errorf("old kid: %w", err)
	}
	oldPEM, err := utils.EncodePublicKeyPEM(oldPub)
	if err != nil {
		return nil, fmt.Errorf("old public key: %w", err)
	}
	next, nextPEM, err := s.generate()
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}
	nextKid, err := utils.ComputeKid(next.(crypto.Signer).Public(), alg)
	if err != nil {
		return nil, fmt.Errorf("new kid: %w", err)
	}
	if _, err := s.kidStore.Add(ctx, &keys.AddKidRequest{Kid: oldKid, Key: oldPEM, Algorithm: alg, ClientID: issuerClientID, ExpiresAt: time.Now().Add(s.grace)}); err != nil {
		return nil, fmt.Errorf("retire old key: %w", err)
	}
	if _, err := s.keyStore.PutKey(ctx, &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: issuerClientID, Key: nextPEM, Algorithm: alg}}); err != nil {
		return nil, fmt.Errorf("publish new key: %w", err)
	}
	if err := s.source.Rotate(next); err != nil {
		return nil, fmt.Errorf("switch signer: %w", err)
	}
	log.Printf("Rotated the %s signing key: %s -> %s, old key kept for %s", alg, oldKid, nextKid, s.grace)
	return map[string]string{"kid": nextKid, "previous_kid": oldKid, "grace_period": s.grace.String()}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
