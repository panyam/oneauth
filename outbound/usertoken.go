package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/panyam/oneauth/keys"
	"golang.org/x/oauth2"
)

// UserTokenPurpose is the HKDF label UserTokens derives its AES key with,
// so the same master key as an EncryptedKeyStorage gives a different key.
const UserTokenPurpose = "oneauth-outbound-user-token-v1"

// DefaultRaceWait is UserTokens.RaceWait's default.
const DefaultRaceWait = 2 * time.Second

// ErrReconnect means the stored token can't be renewed without the
// person: it expired with no refresh token, or the provider refused the
// refresh token. The app sends the person back through the connect flow.
var ErrReconnect = errors.New("outbound: user token needs a new connect")

// UserTokens keeps people's tokens for one provider, sealed in a
// UserTokenStore, and hands out a StoredUserToken per person. Use one per
// provider, built with NewUserTokens.
//
// Typical use: the connect flow's HandleUserFunc calls Save with the token
// it was given, and code calling the API later uses TokenSource(subject).
type UserTokens struct {
	// Provider is the record key's provider half, such as "github".
	Provider string

	// Store holds the sealed records.
	Store UserTokenStore

	// Config is the OAuth client the tokens were issued to. Only
	// ClientID, ClientSecret and Endpoint.TokenURL are used, to refresh.
	Config *oauth2.Config

	// HTTPClient makes refresh requests. Nil means http.DefaultClient.
	HTTPClient *http.Client

	// RefreshBefore is how long before expiry a token is refreshed. Zero
	// means DefaultRefreshBefore.
	RefreshBefore time.Duration

	// RaceWait is how long a replica whose refresh the provider refused
	// waits for another replica's refreshed token to appear in the store
	// before answering ErrReconnect. The winner's write follows its
	// refresh by one store round trip, so a refusal can arrive first.
	// Zero means DefaultRaceWait.
	RaceWait time.Duration

	// Now overrides time.Now, for tests.
	Now func() time.Time

	sealer *keys.Sealer
	locks  sync.Map // subject -> *sync.Mutex
}

// NewUserTokens returns a UserTokens sealing with an AES key derived from
// masterKeyHex (64 hex characters) under UserTokenPurpose.
func NewUserTokens(provider string, store UserTokenStore, masterKeyHex string, cfg *oauth2.Config) (*UserTokens, error) {
	if provider == "" || store == nil || cfg == nil {
		return nil, fmt.Errorf("outbound: provider, store and config are required")
	}
	sealer, err := keys.NewSealer(masterKeyHex, UserTokenPurpose)
	if err != nil {
		return nil, err
	}
	return &UserTokens{Provider: provider, Store: store, Config: cfg, sealer: sealer}, nil
}

// Save stores tok for subject, replacing any token already there. A
// connect flow calls it, so it overwrites whatever version it finds,
// retrying a few times if a refresh writes in between.
func (u *UserTokens) Save(ctx context.Context, subject string, tok *oauth2.Token) error {
	if tok == nil || tok.AccessToken == "" {
		return fmt.Errorf("outbound: token has no access token")
	}
	sealed, err := u.seal(subject, tok)
	if err != nil {
		return err
	}
	for range 3 {
		var ver int64
		cur, err := u.Store.GetUserToken(ctx, &GetUserTokenRequest{Provider: u.Provider, Subject: subject})
		switch {
		case err == nil:
			ver = cur.Record.Version
		case !errors.Is(err, ErrUserTokenNotFound):
			return err
		}
		_, err = u.Store.PutUserToken(ctx, &PutUserTokenRequest{Provider: u.Provider, Subject: subject, Sealed: sealed, ExpectedVersion: ver})
		if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	return ErrVersionConflict
}

// Delete removes subject's token: the person disconnected. It doesn't
// revoke the token at the provider.
func (u *UserTokens) Delete(ctx context.Context, subject string) error {
	_, err := u.Store.DeleteUserToken(ctx, &DeleteUserTokenRequest{Provider: u.Provider, Subject: subject})
	return err
}

// TokenSource returns subject's StoredUserToken. It does no I/O; a person
// who hasn't connected shows up as ErrUserTokenNotFound from Token.
func (u *UserTokens) TokenSource(subject string) *StoredUserToken {
	return &StoredUserToken{tokens: u, subject: subject}
}

// StoredUserToken is a TokenSource for one person's stored token. Each
// Token call reads the store, so a token saved or refreshed by another
// replica is seen at once.
type StoredUserToken struct {
	tokens  *UserTokens
	subject string
}

// Token is TokenContext with a background context.
func (s *StoredUserToken) Token() (*oauth2.Token, error) {
	return s.TokenContext(context.Background())
}

// TokenContext returns the stored token, refreshing it first when it is
// within RefreshBefore of expiry. Errors:
//
//   - ErrUserTokenNotFound: the person hasn't connected.
//   - ErrReconnect: the token expired with no refresh token, or the
//     provider refused the refresh token and no other replica had stored
//     a newer one.
//   - keys.ErrSealedOpen (wrapped): the record doesn't open with this
//     master key, or was moved from another person's record.
//
// When the refresh races another replica's, the loser returns the
// winner's stored token. The returned Expiry is RefreshBefore ahead of the
// provider's, as for GitHubAppInstallation.
func (s *StoredUserToken) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	u := s.tokens
	mu, _ := u.locks.LoadOrStore(s.subject, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()

	tok, ver, err := u.load(ctx, s.subject)
	if err != nil {
		return nil, err
	}
	if u.fresh(tok) {
		return u.handOut(tok), nil
	}
	if tok.RefreshToken == "" {
		return nil, fmt.Errorf("%w: token expired and has no refresh token", ErrReconnect)
	}
	next, err := u.refresh(ctx, tok)
	if err != nil {
		var re *oauth2.RetrieveError
		if !errors.As(err, &re) || (re.ErrorCode != "invalid_grant" && re.ErrorCode != "bad_refresh_token") {
			return nil, fmt.Errorf("outbound: refresh: %w", err)
		}
		// Another replica may have used the refresh token first and be
		// about to write its result.
		if again, ok := u.awaitNewer(ctx, s.subject, ver); ok {
			return u.handOut(again), nil
		}
		return nil, fmt.Errorf("%w: provider refused the refresh token (%s)", ErrReconnect, re.ErrorCode)
	}
	sealed, err := u.seal(s.subject, next)
	if err != nil {
		return nil, err
	}
	_, err = u.Store.PutUserToken(ctx, &PutUserTokenRequest{Provider: u.Provider, Subject: s.subject, Sealed: sealed, ExpectedVersion: ver})
	if errors.Is(err, ErrVersionConflict) {
		if again, _, lerr := u.load(ctx, s.subject); lerr == nil && u.fresh(again) {
			return u.handOut(again), nil
		}
		// The winner's token is unusable; ours is live, so use it.
		return u.handOut(next), nil
	}
	if err != nil {
		return nil, err
	}
	return u.handOut(next), nil
}

// awaitNewer polls the store until a fresh token newer than ver appears or
// RaceWait passes.
func (u *UserTokens) awaitNewer(ctx context.Context, subject string, ver int64) (*oauth2.Token, bool) {
	wait := u.RaceWait
	if wait <= 0 {
		wait = DefaultRaceWait
	}
	deadline := time.Now().Add(wait)
	for delay := 10 * time.Millisecond; ; delay = min(delay*2, 200*time.Millisecond) {
		if tok, v, err := u.load(ctx, subject); err == nil && v != ver && u.fresh(tok) {
			return tok, true
		}
		if !time.Now().Add(delay).Before(deadline) {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(delay):
		}
	}
}

// storedToken is the sealed plaintext. Scope keeps what the provider
// granted, since oauth2.Token's Extra doesn't survive JSON.
type storedToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitzero"`
	Scope        string    `json:"scope,omitempty"`
}

func (u *UserTokens) seal(subject string, tok *oauth2.Token) ([]byte, error) {
	st := storedToken{AccessToken: tok.AccessToken, TokenType: tok.TokenType, RefreshToken: tok.RefreshToken, Expiry: tok.Expiry}
	if sc, ok := tok.Extra("scope").(string); ok {
		st.Scope = sc
	}
	plain, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return u.sealer.Seal(plain, u.aad(subject))
}

func (u *UserTokens) load(ctx context.Context, subject string) (*oauth2.Token, int64, error) {
	resp, err := u.Store.GetUserToken(ctx, &GetUserTokenRequest{Provider: u.Provider, Subject: subject})
	if err != nil {
		return nil, 0, err
	}
	plain, err := u.sealer.Open(resp.Record.Sealed, u.aad(subject))
	if err != nil {
		return nil, 0, fmt.Errorf("outbound: user token for %s/%s: %w", u.Provider, subject, err)
	}
	var st storedToken
	if err := json.Unmarshal(plain, &st); err != nil {
		return nil, 0, fmt.Errorf("outbound: user token for %s/%s is malformed", u.Provider, subject)
	}
	tok := &oauth2.Token{AccessToken: st.AccessToken, TokenType: st.TokenType, RefreshToken: st.RefreshToken, Expiry: st.Expiry}
	if st.Scope != "" {
		tok = tok.WithExtra(map[string]any{"scope": st.Scope})
	}
	return tok, resp.Record.Version, nil
}

// aad binds a sealed token to its record, so a ciphertext copied into
// another person's record doesn't open.
func (u *UserTokens) aad(subject string) []byte {
	return []byte("oneauth-user-token\x00" + u.Provider + "\x00" + subject)
}

func (u *UserTokens) refresh(ctx context.Context, tok *oauth2.Token) (*oauth2.Token, error) {
	if u.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, u.HTTPClient)
	}
	// An empty access token makes the source refresh at once.
	return u.Config.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
}

func (u *UserTokens) fresh(tok *oauth2.Token) bool {
	if tok.AccessToken == "" {
		return false
	}
	return tok.Expiry.IsZero() || u.now().Before(tok.Expiry.Add(-u.refreshBefore()))
}

func (u *UserTokens) handOut(tok *oauth2.Token) *oauth2.Token {
	t := *tok
	if !t.Expiry.IsZero() {
		t.Expiry = t.Expiry.Add(-u.refreshBefore())
	}
	return &t
}

func (u *UserTokens) refreshBefore() time.Duration {
	if u.RefreshBefore > 0 {
		return u.RefreshBefore
	}
	return DefaultRefreshBefore
}

func (u *UserTokens) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

var _ oauth2.TokenSource = (*StoredUserToken)(nil)
