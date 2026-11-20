package apiauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/panyam/oneauth/core"
)

// ErrClientAccessKeyRequired is returned by RevokeClientAccess when the
// request names no subject or no client. Revoking with either empty
// could match every user or every client, so it is refused outright.
var ErrClientAccessKeyRequired = errors.New("revoke client access: subject and client_id are required")

// RevokeClientAccessRequest names the user and the client whose access to
// withdraw. Subject must come from the caller's authenticated session,
// never from a form field, so one user can't revoke another user's grant
// by naming it.
type RevokeClientAccessRequest struct {
	Subject  string
	ClientID string
}

// RevokeClientAccessResponse reports what was revoked, for audit logs.
// RevokedFamilies counts the client's refresh-token families for the
// user, and BlacklistedAccessTokens the unexpired access tokens they had
// recorded and that went on the blacklist.
type RevokeClientAccessResponse struct {
	RevokedFamilies         int
	BlacklistedAccessTokens int
}

// ClientAccessRevoker withdraws everything a user gave one client: the
// remembered consent, the client's refresh tokens for the user, and the
// access tokens issued with them. A "connected apps" page calls it when
// the user disconnects an app. Afterwards the client's next /authorize
// shows the consent screen again, its refresh token fails with
// invalid_grant, and its access tokens fail validation wherever the
// validator checks Blacklist.
//
// Two things outlive the revoke briefly, bounded by their lifetimes
// (issue 526). An authorization code issued before it can still be
// redeemed until it expires, DefaultAuthorizationCodeExpiry (60 seconds)
// by default. An access token issued without a refresh token, such as an
// implicit one, was never recorded, so it can't be blacklisted and works
// until it expires (core.TokenExpiryAccessToken, 15 minutes).
//
// Every field is optional, and a nil one skips that part. Build one with
// OneAuth.ClientAccessRevoker to share the OneAuth's refresh store,
// blacklist and hooks.
type ClientAccessRevoker struct {
	// ConsentStore holds the remembered approvals.
	ConsentStore core.ConsentStore

	// RefreshStore holds the refresh tokens. Only tokens whose Subject
	// and ClientID both match the request are revoked, family by family.
	RefreshStore core.RefreshTokenStore

	// Blacklist receives the access tokens the revoked families recorded
	// (RFC 7009 §2.1). Nil leaves them valid until they expire. An
	// access token issued without a refresh token was never recorded, so
	// it stays valid until it expires either way.
	Blacklist core.TokenBlacklist

	// Hooks fires OnTokenRevoked once per revoked family, with the
	// family as sid, so the back-channel logout dispatcher can tell the
	// client the session ended.
	Hooks TokenHooks
}

// ClientAccessRevoker returns a ClientAccessRevoker over consents and
// this OneAuth's RefreshStore, Blacklist and token hooks. consents may be
// nil when remembered consent is off; the revoker then only revokes
// tokens. ConsentStore is a parameter rather than OneAuthConfig field
// because MountAuthorize, not NewOneAuth, owns it.
func (oa *OneAuth) ClientAccessRevoker(consents core.ConsentStore) *ClientAccessRevoker {
	return &ClientAccessRevoker{
		ConsentStore: consents,
		RefreshStore: oa.RefreshStore,
		Blacklist:    oa.Blacklist,
		Hooks:        oa.Hooks.Token,
	}
}

// RevokeClientAccess revokes req.ClientID's refresh-token families for
// req.Subject, blacklists the access tokens they recorded, and then
// deletes the consent grant.
//
// The consent goes last on purpose. If revoking a family fails, the
// grant stays, so the app is still listed and the user can try again.
// The errors from every failed family are joined and returned.
//
// It is idempotent: revoking a client with no grant and no tokens
// succeeds and reports zero. An authorization code issued before the
// call and redeemed after it still yields tokens, since the code store
// is not consulted; codes live for minutes.
func (r *ClientAccessRevoker) RevokeClientAccess(ctx context.Context, req *RevokeClientAccessRequest) (*RevokeClientAccessResponse, error) {
	if req == nil || req.Subject == "" || req.ClientID == "" {
		return nil, ErrClientAccessKeyRequired
	}
	out := &RevokeClientAccessResponse{}
	if r.RefreshStore != nil {
		families, err := r.clientFamilies(ctx, req.Subject, req.ClientID)
		if err != nil {
			return nil, err
		}
		var errs []error
		for _, family := range families {
			resp, err := r.RefreshStore.RevokeTokenFamily(ctx, &core.RevokeTokenFamilyRequest{Family: family})
			if resp != nil {
				core.BlacklistIssuedAccessTokens(r.Blacklist, resp.AccessTokens)
				out.BlacklistedAccessTokens += len(resp.AccessTokens)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("revoke family: %w", err))
				continue
			}
			out.RevokedFamilies++
			r.Hooks.fireOnTokenRevoked(req.Subject, family, req.ClientID)
		}
		if len(errs) > 0 {
			return out, errors.Join(errs...)
		}
	}
	if r.ConsentStore != nil {
		if _, err := r.ConsentStore.RevokeConsent(ctx, &core.RevokeConsentRequest{Subject: req.Subject, ClientID: req.ClientID}); err != nil {
			return out, fmt.Errorf("revoke consent: %w", err)
		}
	}
	return out, nil
}

// clientFamilies lists the families of subject's live refresh tokens
// that clientID holds. A token with no client (the password grant run
// without a client_id) belongs to no app and is left alone.
func (r *ClientAccessRevoker) clientFamilies(ctx context.Context, subject, clientID string) ([]string, error) {
	resp, err := r.RefreshStore.GetSubjectTokens(ctx, &core.GetSubjectTokensRequest{Subject: subject})
	if err != nil {
		return nil, fmt.Errorf("list refresh tokens: %w", err)
	}
	var families []string
	seen := map[string]bool{}
	for _, t := range resp.Tokens {
		if t == nil || t.Subject != subject || t.ClientID != clientID || t.Family == "" || seen[t.Family] {
			continue
		}
		seen[t.Family] = true
		families = append(families, t.Family)
	}
	return families, nil
}
