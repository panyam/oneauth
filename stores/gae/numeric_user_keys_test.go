//go:build !wasm
// +build !wasm

package gae

import (
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/goapplib/dsmigrate"

	"github.com/panyam/oneauth/accounts"
)

// An app that created users with incomplete keys has them at numeric keys (datastore.IDKey),
// and refers to them by that number as a string. With WithNumericUserKeys, the UserStore finds
// and updates them there instead of reporting them missing or creating a second copy.

const legacyUserID = "5635925325381632"

func putNumericKeyedUser(t *testing.T, c *datastore.Client, ns string, props datastore.PropertyList) *datastore.Key {
	t.Helper()
	k := datastore.IDKey(KindUser, 5635925325381632, nil)
	k.Namespace = ns
	if _, err := c.Put(t.Context(), k, &props); err != nil {
		t.Fatal(err)
	}
	return k
}

func nameKeyExists(t *testing.T, c *datastore.Client, ns, id string) bool {
	t.Helper()
	k := datastore.NameKey(KindUser, id, nil)
	k.Namespace = ns
	var props datastore.PropertyList
	err := c.Get(t.Context(), k, &props)
	if err != nil && err != datastore.ErrNoSuchEntity {
		t.Fatal(err)
	}
	return err == nil
}

func TestUserStore_NumericUserKeys(t *testing.T) {
	ctx, c, ns := schemaTestClient(t)
	created := time.Date(2023, 1, 14, 10, 48, 11, 0, time.UTC)
	idKey := putNumericKeyedUser(t, c, ns, datastore.PropertyList{
		{Name: "is_active", Value: true},
		{Name: "created_at", Value: created},
		{Name: "updated_at", Value: created},
	})
	store := NewUserStore(c, ns, WithNumericUserKeys())

	got, err := store.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: legacyUserID})
	if err != nil {
		t.Fatalf("GetUserById: %v", err)
	}
	if got.User.Id() != legacyUserID || !got.User.(*GAEUser).Active {
		t.Errorf("loaded %+v", got.User)
	}

	if _, err := store.SaveUser(ctx, &accounts.SaveUserRequest{User: &GAEUser{UserID: legacyUserID, Active: true, UserProfile: map[string]any{"name": "Alice"}}}); err != nil {
		t.Fatalf("SaveUser: %v", err)
	}
	var saved UserEntity
	if err := c.Get(ctx, idKey, &saved); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved.Profile), "Alice") || !saved.CreatedAt.Equal(created) {
		t.Errorf("numeric-keyed user after SaveUser: profile %s, created %v", saved.Profile, saved.CreatedAt)
	}
	if nameKeyExists(t, c, ns, legacyUserID) {
		t.Error("SaveUser created a second copy at the name key")
	}
}

func TestUserStore_NumericUserKeysWithSchemaRegistry(t *testing.T) {
	ctx, c, ns := schemaTestClient(t)
	idKey := putNumericKeyedUser(t, c, ns, datastore.PropertyList{
		{Name: "isActive", Value: true},
		{Name: "createdAt", Value: time.Date(2023, 1, 14, 10, 48, 11, 0, time.UTC)},
	})
	reg, err := dsmigrate.NewRegistry(dsmigrate.Schema{
		Kind:    KindUser,
		Current: 1,
		Upgrades: map[int]dsmigrate.Upgrader{0: func(in datastore.PropertyList) (datastore.PropertyList, error) {
			rename := map[string]string{"isActive": "is_active", "createdAt": "created_at"}
			var out datastore.PropertyList
			for _, p := range in {
				if to, ok := rename[p.Name]; ok {
					p.Name = to
				}
				out = append(out, p)
			}
			return out, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := NewUserStore(c, ns, WithNumericUserKeys(), WithSchemaRegistry(reg))

	got, err := store.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: legacyUserID})
	if err != nil || !got.User.(*GAEUser).Active {
		t.Fatalf("GetUserById: %+v err %v", got, err)
	}
	var stored datastore.PropertyList
	if err := c.Get(ctx, idKey, &stored); err != nil {
		t.Fatal(err)
	}
	if v := dsmigrate.Version(stored); v != 1 {
		t.Errorf("numeric-keyed user's stored version = %d, want 1", v)
	}
}

func TestUserStore_NumericUserKeysOffByDefault(t *testing.T) {
	ctx, c, ns := schemaTestClient(t)
	putNumericKeyedUser(t, c, ns, datastore.PropertyList{{Name: "is_active", Value: true}})
	if _, err := NewUserStore(c, ns).GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: legacyUserID}); err == nil {
		t.Error("found a numeric-keyed user without WithNumericUserKeys")
	}
	// Only canonical decimal IDs map to a numeric key.
	store := NewUserStore(c, ns, WithNumericUserKeys())
	for _, id := range []string{"0" + legacyUserID, "+" + legacyUserID, "not-a-number"} {
		if _, err := store.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: id}); err == nil {
			t.Errorf("GetUserById(%q) found the numeric-keyed user", id)
		}
	}
}
