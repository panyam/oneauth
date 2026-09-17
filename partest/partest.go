// Package partest provides a shared contract test suite for every
// core.PushedAuthorizationRequestStore implementation (RFC 9126). Each
// backend hands this package a Factory closure and calls RunAll, so
// in-memory and GORM answer the same questions about expiry, consumption
// and client binding. Mirrors the authcodetest and deviceauthtest
// precedents.
//
// Why a shared suite: the interesting behavior here is not storage, it is
// the three states a request_uri moves through (live, consumed, expired)
// and the fact that a backend must keep them distinguishable. A backend
// that collapses "consumed" into "gone" passes a naive per-backend test and
// breaks the error a client is owed.
package partest

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

// Backend is the per-scenario fixture. Store is the handle under test;
// Reopen returns a fresh handle over the same backing storage so
// RestartPersists can simulate a process restart. In-memory backends return
// the same instance, where the property holds trivially.
type Backend struct {
	Store  core.PushedAuthorizationRequestStore
	Reopen func() core.PushedAuthorizationRequestStore
}

// Factory creates a Backend per scenario. Persistent backends must close
// over per-test state (a *gorm.DB, a tempdir) so Store and Reopen resolve to
// the same storage within one scenario.
type Factory func(t *testing.T) Backend

// RunAll runs the complete contract suite against the provided factory.
func RunAll(t *testing.T, factory Factory) {
	t.Run("CreateAndGet", func(t *testing.T) { TestCreateAndGet(t, factory) })
	t.Run("NotFound", func(t *testing.T) { TestNotFound(t, factory) })
	t.Run("Collision", func(t *testing.T) { TestCollision(t, factory) })
	t.Run("ConsumeMarksWithoutDeleting", func(t *testing.T) { TestConsumeMarksWithoutDeleting(t, factory) })
	t.Run("Delete", func(t *testing.T) { TestDelete(t, factory) })
	t.Run("CleanupExpired", func(t *testing.T) { TestCleanupExpired(t, factory) })
	t.Run("RestartPersists", func(t *testing.T) { TestRestartPersists(t, factory) })
}

const testRequestURI = core.PushedRequestURIPrefix + "abc123"

func newRequest() *core.PushedAuthorizationRequest {
	return &core.PushedAuthorizationRequest{
		RequestURI: testRequestURI,
		ClientID:   "client-x",
		Payload: url.Values{
			"client_id":             {"client-x"},
			"response_type":         {"code"},
			"redirect_uri":          {"https://app.example/cb"},
			"scope":                 {"read write"},
			"code_challenge":        {"challenge"},
			"code_challenge_method": {"S256"},
			"authorization_details": {`[{"type":"payment","amount":"42"}]`},
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}
}

func create(t *testing.T, s core.PushedAuthorizationRequestStore, r *core.PushedAuthorizationRequest) {
	t.Helper()
	_, err := s.CreatePushedAuthorizationRequest(context.Background(), &core.CreatePushedAuthorizationRequestRequest{Request: r})
	require.NoError(t, err)
}

func get(t *testing.T, s core.PushedAuthorizationRequestStore, uri string) (*core.PushedAuthorizationRequest, error) {
	t.Helper()
	resp, err := s.GetPushedAuthorizationRequest(context.Background(), &core.GetPushedAuthorizationRequestRequest{RequestURI: uri})
	if err != nil {
		return nil, err
	}
	return resp.Request, nil
}

// TestCreateAndGet pins the round trip, and in particular that the payload
// survives it unchanged. The payload is the whole point of PAR: a backend
// that drops or reorders parameters silently changes the authorization
// request between the push and the redirect. `authorization_details` is in
// the fixture because RFC 9396 JSON is the payload most likely to be
// mangled by a serializer.
func TestCreateAndGet(t *testing.T, factory Factory) {
	s := factory(t).Store
	create(t, s, newRequest())

	got, err := get(t, s, testRequestURI)
	require.NoError(t, err)
	assert.Equal(t, "client-x", got.ClientID)
	assert.False(t, got.Consumed)
	assert.Equal(t, "code", got.Payload.Get("response_type"))
	assert.Equal(t, "read write", got.Payload.Get("scope"))
	assert.Equal(t, `[{"type":"payment","amount":"42"}]`, got.Payload.Get("authorization_details"),
		"the pushed payload MUST round-trip verbatim, including extension parameters the store does not understand")
}

// TestNotFound pins the sentinel. The authorization endpoint maps it to
// "unknown request_uri"; a generic error would surface as a 500 and tell a
// client nothing it can act on.
func TestNotFound(t *testing.T, factory Factory) {
	s := factory(t).Store

	_, err := get(t, s, core.PushedRequestURIPrefix+"missing")

	require.True(t, errors.Is(err, core.ErrPushedRequestNotFound))
}

// TestCollision pins that a repeated request_uri is refused rather than
// overwritten. Overwriting would let a second push replace the payload
// behind a reference the first client is about to redirect with.
func TestCollision(t *testing.T, factory Factory) {
	s := factory(t).Store
	create(t, s, newRequest())

	_, err := s.CreatePushedAuthorizationRequest(context.Background(), &core.CreatePushedAuthorizationRequestRequest{Request: newRequest()})

	require.Error(t, err, "a request_uri collision MUST be rejected")
}

// TestConsumeMarksWithoutDeleting pins the distinction the interface
// promises: a consumed reference is still readable and reports Consumed.
// A backend that deletes on consume makes "already used" indistinguishable
// from "never existed", and the client gets the wrong error.
func TestConsumeMarksWithoutDeleting(t *testing.T, factory Factory) {
	s := factory(t).Store
	create(t, s, newRequest())

	_, err := s.ConsumePushedAuthorizationRequest(context.Background(), &core.ConsumePushedAuthorizationRequestRequest{RequestURI: testRequestURI})
	require.NoError(t, err)

	got, err := get(t, s, testRequestURI)
	require.NoError(t, err, "a consumed request MUST remain readable")
	assert.True(t, got.Consumed)
	assert.False(t, got.IsUsable(time.Now()), "a consumed request MUST NOT be usable")

	_, err = s.ConsumePushedAuthorizationRequest(context.Background(), &core.ConsumePushedAuthorizationRequestRequest{RequestURI: core.PushedRequestURIPrefix + "missing"})
	require.True(t, errors.Is(err, core.ErrPushedRequestNotFound))
}

func TestDelete(t *testing.T, factory Factory) {
	s := factory(t).Store
	create(t, s, newRequest())

	_, err := s.DeletePushedAuthorizationRequest(context.Background(), &core.DeletePushedAuthorizationRequestRequest{RequestURI: testRequestURI})
	require.NoError(t, err)

	_, err = get(t, s, testRequestURI)
	require.True(t, errors.Is(err, core.ErrPushedRequestNotFound))

	_, err = s.DeletePushedAuthorizationRequest(context.Background(), &core.DeletePushedAuthorizationRequestRequest{RequestURI: testRequestURI})
	require.True(t, errors.Is(err, core.ErrPushedRequestNotFound),
		"a second delete MUST return the sentinel so callers can tell 'never existed' from 'already gone'")
}

// TestCleanupExpired pins the sweep, including that it takes consumed
// records with it. Consumed rows are what a store accumulates most of, so a
// sweep that skipped them would grow without bound.
func TestCleanupExpired(t *testing.T, factory Factory) {
	s := factory(t).Store
	now := time.Now()

	expired := newRequest()
	expired.RequestURI = core.PushedRequestURIPrefix + "expired"
	expired.ExpiresAt = now.Add(-time.Minute)
	create(t, s, expired)

	consumedExpired := newRequest()
	consumedExpired.RequestURI = core.PushedRequestURIPrefix + "consumed"
	consumedExpired.ExpiresAt = now.Add(-time.Minute)
	consumedExpired.Consumed = true
	create(t, s, consumedExpired)

	live := newRequest()
	live.RequestURI = core.PushedRequestURIPrefix + "live"
	live.ExpiresAt = now.Add(time.Minute)
	create(t, s, live)

	resp, err := s.CleanupExpiredPushedRequests(context.Background(), &core.CleanupExpiredPushedRequestsRequest{})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Removed)

	_, err = get(t, s, core.PushedRequestURIPrefix+"live")
	assert.NoError(t, err, "a live request MUST survive the sweep")
}

func TestRestartPersists(t *testing.T, factory Factory) {
	b := factory(t)
	create(t, b.Store, newRequest())

	got, err := b.Reopen().GetPushedAuthorizationRequest(context.Background(), &core.GetPushedAuthorizationRequestRequest{RequestURI: testRequestURI})

	require.NoError(t, err)
	assert.Equal(t, "client-x", got.Request.ClientID)
}
