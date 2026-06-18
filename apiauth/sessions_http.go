package apiauth

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/panyam/oneauth/core"
)

// SessionsHandler serves the per-user session-management endpoints:
//
//	POST /api/logout      → revoke a single refresh token (HandleLogout)
//	POST /api/logout-all  → revoke every refresh token for the caller (HandleLogoutAll)
//	GET  /api/sessions    → list the caller's active sessions (HandleListSessions)
//
// The caller's identity is read from the request context, populated
// upstream by APIMiddleware. HandleLogout reads the refresh token from
// the JSON body and does not require authentication; the other two
// endpoints require an authenticated subject.
//
// TokenHooks fire on revoke so the OIDC Back-Channel Logout
// dispatcher (and any other subscriber) can fan out notifications.
type SessionsHandler struct {
	// Store backs the refresh tokens. Required.
	Store core.RefreshTokenStore

	// Hooks fires the lifecycle callbacks. The zero value is a no-op
	// dispatcher.
	Hooks TokenHooks
}

// NewSessionsHandler constructs a SessionsHandler.
func NewSessionsHandler(store core.RefreshTokenStore, hooks TokenHooks) *SessionsHandler {
	return &SessionsHandler{Store: store, Hooks: hooks}
}

// HandleLogout serves POST /api/logout — revokes one refresh token.
// Does not require authentication; the token in the body is the
// proof. Errors are not surfaced (don't reveal whether the token
// existed).
func (h *SessionsHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIErrorJSON(w, "invalid_request", "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeAPIErrorJSON(w, "invalid_request", "refresh_token required", http.StatusBadRequest)
		return
	}

	// Capture subject + family + client_id BEFORE revoke so the BCL
	// dispatcher knows who to notify. Get-then-Revoke rather than a
	// single store call because the store interface doesn't expose a
	// "revoke-and-return" form; a missing token leaves all three
	// fields empty which the dispatcher already handles.
	var sub, sid, clientID string
	if getResp, err := h.Store.GetRefreshToken(r.Context(), &core.GetRefreshTokenRequest{Token: req.RefreshToken}); err == nil && getResp != nil && getResp.Token != nil {
		sub = getResp.Token.Subject
		sid = getResp.Token.Family
		clientID = getResp.Token.ClientID
	}

	if _, err := h.Store.RevokeRefreshToken(r.Context(), &core.RevokeRefreshTokenRequest{Token: req.RefreshToken}); err != nil {
		log.Printf("revoke refresh token: %v", err)
	}

	if sub != "" {
		h.Hooks.fireOnTokenRevoked(sub, sid, clientID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleLogoutAll serves POST /api/logout-all — revokes every refresh
// token for the authenticated caller. The subject MUST be present in
// the request context (set by upstream middleware).
func (h *SessionsHandler) HandleLogoutAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIErrorJSON(w, "invalid_request", "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := core.GetSubjectFromContext(r.Context())
	if userID == "" {
		writeAPIErrorJSON(w, "unauthorized", "authentication required", http.StatusUnauthorized)
		return
	}

	// Capture the affected client_ids BEFORE revoke so the BCL
	// dispatcher can notify each — GetSubjectTokens returns only
	// active grants and would yield an empty set if called after
	// RevokeSubjectTokens.
	var clientIDs []string
	if getResp, err := h.Store.GetSubjectTokens(r.Context(), &core.GetSubjectTokensRequest{Subject: userID}); err == nil && getResp != nil {
		seen := map[string]struct{}{}
		for _, t := range getResp.Tokens {
			if t == nil || t.ClientID == "" {
				continue
			}
			if _, ok := seen[t.ClientID]; ok {
				continue
			}
			seen[t.ClientID] = struct{}{}
			clientIDs = append(clientIDs, t.ClientID)
		}
	}

	if _, err := h.Store.RevokeSubjectTokens(r.Context(), &core.RevokeSubjectTokensRequest{Subject: userID}); err != nil {
		log.Printf("revoke subject tokens: %v", err)
		writeAPIErrorJSON(w, "server_error", "failed to revoke sessions", http.StatusInternalServerError)
		return
	}

	// sid is empty — logout-all crosses every session for the user.
	h.Hooks.fireOnSubjectRevoked(userID, "", clientIDs)

	w.WriteHeader(http.StatusNoContent)
}

// HandleListSessions serves GET /api/sessions — returns the caller's
// active sessions with device metadata.
func (h *SessionsHandler) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIErrorJSON(w, "invalid_request", "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := core.GetSubjectFromContext(r.Context())
	if userID == "" {
		writeAPIErrorJSON(w, "unauthorized", "authentication required", http.StatusUnauthorized)
		return
	}

	getResp, err := h.Store.GetSubjectTokens(r.Context(), &core.GetSubjectTokensRequest{Subject: userID})
	if err != nil {
		log.Printf("list sessions: %v", err)
		writeAPIErrorJSON(w, "server_error", "failed to get sessions", http.StatusInternalServerError)
		return
	}

	type sessionInfo struct {
		ID         string    `json:"id"`
		DeviceInfo any       `json:"device_info,omitempty"`
		CreatedAt  time.Time `json:"created_at"`
		LastUsedAt time.Time `json:"last_used_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		Scopes     []string  `json:"scopes,omitempty"`
	}

	sessions := make([]sessionInfo, 0, len(getResp.Tokens))
	for _, t := range getResp.Tokens {
		sessions = append(sessions, sessionInfo{
			ID:         t.TokenHash[:16], // partial hash as a stable id
			DeviceInfo: t.DeviceInfo,
			CreatedAt:  t.CreatedAt,
			LastUsedAt: t.LastUsedAt,
			ExpiresAt:  t.ExpiresAt,
			Scopes:     t.Scopes,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": sessions})
}
