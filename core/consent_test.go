package core_test

import (
	"testing"
	"time"

	"github.com/panyam/oneauth/consenttest"
	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryConsentStore_Contract(t *testing.T) {
	consenttest.RunAll(t, func(t *testing.T) consenttest.Backend {
		s := core.NewInMemoryConsentStore()
		return consenttest.Backend{Store: s, Reopen: func() core.ConsentStore { return s }}
	})
}

func TestConsentGrant_Covers(t *testing.T) {
	now := time.Now()
	g := &core.ConsentGrant{Scopes: []string{"openid", "email"}, ExpiresAt: now.Add(time.Minute)}
	assert.True(t, g.Covers([]string{"openid"}, now))
	assert.True(t, g.Covers(nil, now), "an empty request is covered")
	assert.False(t, g.Covers([]string{"openid", "profile"}, now), "every scope must be covered")
	assert.False(t, g.Covers([]string{"openid"}, now.Add(time.Minute)), "expired at ExpiresAt")
	assert.True(t, (&core.ConsentGrant{Scopes: []string{"openid"}}).Covers([]string{"openid"}, now.Add(1000*time.Hour)), "zero ExpiresAt never expires")
	assert.False(t, (*core.ConsentGrant)(nil).Covers(nil, now))
}
