package gae

// Grants saved before issue 516 have no indexed subject, so ListConsents
// misses them. GetConsent repairs one when it reads it, and
// BackfillConsentSubjects repairs them all (issue 526).
// See: https://github.com/panyam/oneauth/issues/526

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

// putLegacyConsent writes a grant the way the store did before issue 516,
// with no subject property.
func putLegacyConsent(t *testing.T, s *GAEConsentStore, subject, clientID string) {
	t.Helper()
	now := time.Now()
	b, err := json.Marshal(&core.ConsentGrant{Subject: subject, ClientID: clientID, Scopes: []string{"openid"}, GrantedAt: now, ExpiresAt: now.Add(time.Hour)})
	require.NoError(t, err)
	_, err = s.client.Put(context.Background(), s.key(subject, clientID), &ConsentEntity{Record: b})
	require.NoError(t, err)
}

func listedClients(t *testing.T, s *GAEConsentStore, subject string) []string {
	t.Helper()
	resp, err := s.ListConsents(context.Background(), &core.ListConsentsRequest{Subject: subject})
	require.NoError(t, err)
	var out []string
	for _, g := range resp.Grants {
		out = append(out, g.ClientID)
	}
	return out
}

func TestGAEConsentStore_GetConsentRepairsALegacyGrant(t *testing.T) {
	const ns = "consent-legacy-get"
	client, _ := emulatorClient(t, KindConsent, ns)
	s := NewConsentStore(client, ns)
	putLegacyConsent(t, s, "alice", "app-a")
	require.Empty(t, listedClients(t, s, "alice"), "fixture: a legacy grant isn't listed")

	_, err := s.GetConsent(context.Background(), &core.GetConsentRequest{Subject: "alice", ClientID: "app-a"})
	require.NoError(t, err)
	assert.Equal(t, []string{"app-a"}, listedClients(t, s, "alice"))
}

func TestGAEConsentStore_BackfillConsentSubjects(t *testing.T) {
	const ns = "consent-legacy-backfill"
	client, _ := emulatorClient(t, KindConsent, ns)
	s := NewConsentStore(client, ns)
	putLegacyConsent(t, s, "alice", "app-a")
	putLegacyConsent(t, s, "alice", "app-b")
	_, err := s.SaveConsent(context.Background(), &core.SaveConsentRequest{Grant: &core.ConsentGrant{
		Subject: "bob", ClientID: "app-a", Scopes: []string{"openid"}, GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}})
	require.NoError(t, err)

	n, err := s.BackfillConsentSubjects(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n, "only the legacy grants are rewritten")
	assert.Equal(t, []string{"app-a", "app-b"}, listedClients(t, s, "alice"))
	assert.Equal(t, []string{"app-a"}, listedClients(t, s, "bob"))

	n, err = s.BackfillConsentSubjects(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "a second run finds nothing to do")
}
