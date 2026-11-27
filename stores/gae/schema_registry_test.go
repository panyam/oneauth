//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/goapplib/dsmigrate"

	"github.com/panyam/oneauth/accounts"
)

// An app that kept identities in its own shape before adopting oneauth registers an upgrader
// for them. The stores then read those identities through it: a login finds the user, the
// entity is stored in oneauth's shape afterwards, and a backfill reaches the ones nobody read,
// so GetUserIdentities finds them too.

func schemaTestClient(t *testing.T) (context.Context, *datastore.Client, string) {
	t.Helper()
	project := os.Getenv("DATASTORE_PROJECT_ID")
	if project == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping the schema registry tests")
	}
	ctx := context.Background()
	c, err := datastore.NewClient(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return ctx, c, fmt.Sprintf("oneauth-schema-%d", time.Now().UnixNano())
}

// legacyIdentitySchema upgrades an app's pre-oneauth identity (identityType, identityKey,
// primaryUser, isActive) to IdentityEntity's properties.
func legacyIdentitySchema() dsmigrate.Schema {
	return dsmigrate.Schema{
		Kind:    KindIdentity,
		Current: 1,
		Upgrades: map[int]dsmigrate.Upgrader{
			0: func(in datastore.PropertyList) (datastore.PropertyList, error) {
				rename := map[string]string{"identityType": "type", "identityKey": "value", "primaryUser": "user_id"}
				var out datastore.PropertyList
				for _, p := range in {
					if p.Name == "isActive" {
						continue
					}
					if to, ok := rename[p.Name]; ok {
						p.Name = to
					}
					out = append(out, p)
				}
				return out, nil
			},
		},
	}
}

func putLegacyIdentity(t *testing.T, ctx context.Context, c *datastore.Client, ns, email, user string) *datastore.Key {
	t.Helper()
	k := datastore.NameKey(KindIdentity, "email:"+email, nil)
	k.Namespace = ns
	props := datastore.PropertyList{
		{Name: "identityType", Value: "email"},
		{Name: "identityKey", Value: email},
		{Name: "primaryUser", Value: user},
		{Name: "isActive", Value: true},
	}
	if _, err := c.Put(ctx, k, &props); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestIdentityStore_SchemaRegistryUpgradesLegacyIdentities(t *testing.T) {
	ctx, c, ns := schemaTestClient(t)
	reg, err := dsmigrate.NewRegistry(legacyIdentitySchema())
	if err != nil {
		t.Fatal(err)
	}
	store := NewIdentityStore(c, ns, WithSchemaRegistry(reg))
	k := putLegacyIdentity(t, ctx, c, ns, "alice@example.com", "user-alice")

	got, err := store.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: "alice@example.com"})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if got.Identity.UserID != "user-alice" {
		t.Errorf("UserID = %q, want user-alice", got.Identity.UserID)
	}
	var stored datastore.PropertyList
	if err := c.Get(ctx, k, &stored); err != nil {
		t.Fatal(err)
	}
	if v := dsmigrate.Version(stored); v != 1 {
		t.Errorf("stored version = %d, want 1", v)
	}

	// Bob's identity was never read, so the query can't see it until a backfill runs.
	putLegacyIdentity(t, ctx, c, ns, "bob@example.com", "user-bob")
	list, err := store.GetUserIdentities(ctx, &accounts.GetUserIdentitiesRequest{UserID: "user-bob"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Identities) != 0 {
		t.Fatalf("found bob's unread legacy identity before the backfill: %+v", list.Identities)
	}
	report, err := dsmigrate.Backfill(ctx, c, KindIdentity, reg, dsmigrate.BackfillOptions{Namespace: ns})
	if err != nil || report.Upgraded != 1 {
		t.Fatalf("Backfill: %+v err %v", report, err)
	}
	list, err = store.GetUserIdentities(ctx, &accounts.GetUserIdentitiesRequest{UserID: "user-bob"})
	if err != nil || len(list.Identities) != 1 || list.Identities[0].Value != "bob@example.com" {
		t.Errorf("after backfill: %+v err %v", list, err)
	}
}

func TestIdentityStore_WritesStampTheVersion(t *testing.T) {
	ctx, c, ns := schemaTestClient(t)
	reg, _ := dsmigrate.NewRegistry(legacyIdentitySchema())
	store := NewIdentityStore(c, ns, WithSchemaRegistry(reg))

	if _, err := store.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: "new@example.com", CreateIfMissing: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkIdentityVerified(ctx, &accounts.MarkIdentityVerifiedRequest{IdentityType: "email", IdentityValue: "new@example.com"}); err != nil {
		t.Fatal(err)
	}
	k := datastore.NameKey(KindIdentity, "email:new@example.com", nil)
	k.Namespace = ns
	var stored datastore.PropertyList
	if err := c.Get(ctx, k, &stored); err != nil {
		t.Fatal(err)
	}
	if v := dsmigrate.Version(stored); v != 1 {
		t.Errorf("version after create and a transactional update = %d, want 1", v)
	}
}

func TestIdentityStore_WithoutRegistryIsUnchanged(t *testing.T) {
	ctx, c, ns := schemaTestClient(t)
	store := NewIdentityStore(c, ns)
	if _, err := store.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: "plain@example.com", CreateIfMissing: true}); err != nil {
		t.Fatal(err)
	}
	k := datastore.NameKey(KindIdentity, "email:plain@example.com", nil)
	k.Namespace = ns
	var stored datastore.PropertyList
	if err := c.Get(ctx, k, &stored); err != nil {
		t.Fatal(err)
	}
	for _, p := range stored {
		if p.Name == dsmigrate.VersionProperty {
			t.Errorf("a store without a registry wrote %s", dsmigrate.VersionProperty)
		}
	}
}
