// Package authcodetest provides a shared contract test suite for all
// core.AuthorizationCodeStore implementations (RFC 6749 §4.1). Each
// backend — in-memory, fs (follow-up), gorm (follow-up), gae
// (follow-up) — exercises the same behavioral scenarios by handing
// this package a Factory closure and calling RunAll. Mirrors the
// existing deviceauthtest precedent.
//
// Why a shared suite: the per-backend test files for the device store
// had started to drift on small details (error wording, scope
// round-trip, LastPolledAt persistence). Pulling the scenarios into one
// place enforces the contract uniformly and makes adding the next
// backend a one-line RunAll invocation.
package authcodetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Backend is the per-test fixture handed to every scenario. Store is
// the initial handle the test exercises; Reopen returns a fresh handle
// bound to the same backing storage so the RestartPersists scenario
// can simulate a process restart.
//
// For persistent backends (fs / gorm / gae) Reopen constructs a new
// store rooted at the same dir / DB connection / namespace. For the
// in-memory backend Reopen returns the same instance — there is no
// underlying storage to reconnect to and the property the scenario
// pins ("data survives a fresh handle") is trivially true.
type Backend struct {
	Store  core.AuthorizationCodeStore
	Reopen func() core.AuthorizationCodeStore
}

// Factory creates a Backend per scenario. Persistent backends MUST
// close over per-test state (a tempdir from t.TempDir(), a *gorm.DB, a
// datastore namespace) so Store and Reopen both resolve to the same
// underlying storage within one scenario.
type Factory func(t *testing.T) Backend

// RunAll runs the complete AuthorizationCodeStore contract suite
// against the provided factory. Each scenario gets a fresh Backend via
// factory(t) so state cannot leak between cases.
func RunAll(t *testing.T, factory Factory) {
	t.Run("CreateAndGet", func(t *testing.T) { TestCreateAndGet(t, factory) })
	t.Run("NotFound", func(t *testing.T) { TestNotFound(t, factory) })
	t.Run("Collision", func(t *testing.T) { TestCollision(t, factory) })
	t.Run("DeleteConsumes", func(t *testing.T) { TestDeleteConsumes(t, factory) })
	t.Run("CleanupExpired", func(t *testing.T) { TestCleanupExpired(t, factory) })
	t.Run("RestartPersists", func(t *testing.T) { TestRestartPersists(t, factory) })
}

func newCode() *core.AuthorizationCode {
	return &core.AuthorizationCode{
		Code:                "code-abc",
		ClientID:            "client-x",
		RedirectURI:         "https://app.example/cb",
		Scopes:              []string{"read", "write"},
		Subject:             "user-1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		IssuedAt:            time.Now(),
		ExpiresAt:           time.Now().Add(1 * time.Minute),
	}
}

func createCode(t *testing.T, s core.AuthorizationCodeStore, c *core.AuthorizationCode) {
	t.Helper()
	_, err := s.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{Code: c})
	require.NoError(t, err)
}

// TestCreateAndGet pins the happy-path round-trip: a freshly stored
// code returns every binding field unchanged on lookup. Pinning Scopes
// catches backends that drop the slice during JSON / SQL marshalling.
func TestCreateAndGet(t *testing.T, factory Factory) {
	s := factory(t).Store
	createCode(t, s, newCode())

	g, err := s.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "code-abc"})
	require.NoError(t, err)
	assert.Equal(t, "code-abc", g.Code.Code)
	assert.Equal(t, "client-x", g.Code.ClientID)
	assert.Equal(t, "https://app.example/cb", g.Code.RedirectURI)
	assert.Equal(t, "user-1", g.Code.Subject)
	assert.Equal(t, "challenge", g.Code.CodeChallenge)
	assert.Equal(t, "S256", g.Code.CodeChallengeMethod)
	assert.Equal(t, []string{"read", "write"}, g.Code.Scopes, "Scopes slice MUST round-trip through the backend's serialization")
}

// TestNotFound pins that GetAuthorizationCode returns
// ErrAuthorizationCodeNotFound (not a generic error) when the record
// does not exist. The redemption handler maps the sentinel to
// `invalid_grant` per RFC 6749 §5.2; a generic error would surface as
// a 500.
func TestNotFound(t *testing.T, factory Factory) {
	s := factory(t).Store
	_, err := s.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "missing"})
	require.True(t, errors.Is(err, core.ErrAuthorizationCodeNotFound))
}

// TestCollision pins that re-creating a code is rejected. The code is
// the AS-issued unique handle the client redeems with; a
// silently-overwritten record would let a second client hijack the
// first's pending authorization.
func TestCollision(t *testing.T, factory Factory) {
	s := factory(t).Store
	createCode(t, s, newCode())
	_, err := s.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{Code: newCode()})
	require.Error(t, err, "code collision MUST be rejected")
}

// TestDeleteConsumes pins single-use semantics: a code that has been
// deleted is no longer reachable via GetAuthorizationCode. The
// redemption handler relies on this for replay protection — RFC 6749
// §4.1.2 mandates that the AS MUST invalidate the code after first
// use.
func TestDeleteConsumes(t *testing.T, factory Factory) {
	s := factory(t).Store
	createCode(t, s, newCode())

	_, err := s.DeleteAuthorizationCode(context.Background(), &core.DeleteAuthorizationCodeRequest{Code: "code-abc"})
	require.NoError(t, err)

	_, err = s.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "code-abc"})
	require.True(t, errors.Is(err, core.ErrAuthorizationCodeNotFound))

	_, err = s.DeleteAuthorizationCode(context.Background(), &core.DeleteAuthorizationCodeRequest{Code: "code-abc"})
	require.True(t, errors.Is(err, core.ErrAuthorizationCodeNotFound), "second delete MUST return the sentinel so callers can distinguish 'never existed' from 'already consumed'")
}

// TestCleanupExpired pins the timer-driven sweep contract: codes with
// ExpiresAt at or before now are removed; codes still in their window
// survive.
func TestCleanupExpired(t *testing.T, factory Factory) {
	s := factory(t).Store
	now := time.Now()

	expired := newCode()
	expired.Code = "expired"
	expired.ExpiresAt = now.Add(-1 * time.Minute)
	createCode(t, s, expired)

	live := newCode()
	live.Code = "live"
	live.ExpiresAt = now.Add(1 * time.Minute)
	createCode(t, s, live)

	resp, err := s.CleanupExpired(context.Background(), &core.CleanupExpiredAuthorizationCodesRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Removed, "expired records MUST be removed")

	_, err = s.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "expired"})
	assert.True(t, errors.Is(err, core.ErrAuthorizationCodeNotFound))

	_, err = s.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "live"})
	assert.NoError(t, err, "non-expired records MUST survive cleanup")
}

// TestRestartPersists pins durability for persistent backends. The
// scenario writes a code through the initial Store handle, reopens via
// Reopen, and reads the code back. For the in-memory backend this is
// trivially true (Reopen returns the same instance).
func TestRestartPersists(t *testing.T, factory Factory) {
	b := factory(t)
	createCode(t, b.Store, newCode())

	s2 := b.Reopen()
	g, err := s2.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "code-abc"})
	require.NoError(t, err)
	assert.Equal(t, "user-1", g.Code.Subject)
}
