// Package channeltest is the shared contract suite for accounts.ChannelAdmin,
// the optional interface for listing a ChannelStore's channels and deleting
// one. Each backend runs RunAdmin with a factory that returns a fresh, empty
// store.
package channeltest

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/panyam/oneauth/accounts"
)

// Store is a ChannelStore that also implements ChannelAdmin.
type Store interface {
	accounts.ChannelStore
	accounts.ChannelAdmin
}

// Backend is one fresh, empty store. Reopen returns a second handle on the
// same data, the way another process would see it. For fs that's a store on
// the same directory.
type Backend struct {
	Store  Store
	Reopen func() Store
}

// Factory returns a fresh, empty backend for one subtest.
type Factory func(t *testing.T) Backend

// RunAdmin runs every ChannelAdmin contract test against factory.
func RunAdmin(t *testing.T, factory Factory) {
	t.Run("ListEmpty", func(t *testing.T) { TestListEmpty(t, factory) })
	t.Run("ListByProviderWithoutCredentials", func(t *testing.T) { TestListByProviderWithoutCredentials(t, factory) })
	t.Run("ListEveryProvider", func(t *testing.T) { TestListEveryProvider(t, factory) })
	t.Run("DeleteRemovesOnlyTheNamedChannel", func(t *testing.T) { TestDeleteRemovesOnlyTheNamedChannel(t, factory) })
	t.Run("DeleteIsRepeatable", func(t *testing.T) { TestDeleteIsRepeatable(t, factory) })
	t.Run("AnotherHandleSeesTheChanges", func(t *testing.T) { TestAnotherHandleSeesTheChanges(t, factory) })
	t.Run("ListDuringDelete", func(t *testing.T) { TestListDuringDelete(t, factory) })
}

func save(t *testing.T, s accounts.ChannelStore, provider, identityKey string) {
	t.Helper()
	ch := &accounts.Channel{
		Provider:    provider,
		IdentityKey: identityKey,
		Credentials: map[string]any{"password_hash": "$2a$10$not-a-real-hash-" + identityKey},
		Profile:     map[string]any{"username": identityKey},
	}
	if _, err := s.SaveChannel(context.Background(), &accounts.SaveChannelRequest{Channel: ch}); err != nil {
		t.Fatalf("SaveChannel(%s, %s): %v", provider, identityKey, err)
	}
}

func list(t *testing.T, s accounts.ChannelAdmin, provider string) []*accounts.Channel {
	t.Helper()
	resp, err := s.ListChannels(context.Background(), &accounts.ListChannelsRequest{Provider: provider})
	if err != nil {
		t.Fatalf("ListChannels(%q): %v", provider, err)
	}
	return resp.Channels
}

// names lists provider/identityKey for each channel, sorted.
func names(chs []*accounts.Channel) []string {
	out := []string{}
	for _, c := range chs {
		out = append(out, c.Provider+"/"+c.IdentityKey)
	}
	sort.Strings(out)
	return out
}

func del(t *testing.T, s accounts.ChannelAdmin, provider, identityKey string) bool {
	t.Helper()
	resp, err := s.DeleteChannel(context.Background(), &accounts.DeleteChannelRequest{Provider: provider, IdentityKey: identityKey})
	if err != nil {
		t.Fatalf("DeleteChannel(%s, %s): %v", provider, identityKey, err)
	}
	return resp.Deleted
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestListEmpty: an empty store lists no channels and no error, for one
// provider and for all.
func TestListEmpty(t *testing.T, factory Factory) {
	s := factory(t).Store
	for _, p := range []string{"local", ""} {
		if got := list(t, s, p); len(got) != 0 {
			t.Fatalf("ListChannels(%q): want none, got %v", p, names(got))
		}
	}
}

// TestListByProviderWithoutCredentials: listing one provider returns its
// channels alone, each with its profile and without its credentials.
func TestListByProviderWithoutCredentials(t *testing.T, factory Factory) {
	s := factory(t).Store
	save(t, s, "local", "username:alice")
	save(t, s, "local", "username:bob")
	save(t, s, "github", "username:alice")
	got := list(t, s, "local")
	if want := []string{"local/username:alice", "local/username:bob"}; !equal(names(got), want) {
		t.Fatalf("want %v, got %v", want, names(got))
	}
	for _, c := range got {
		if c.Credentials != nil {
			t.Errorf("%s/%s listed with its credentials %v", c.Provider, c.IdentityKey, c.Credentials)
		}
		if c.Profile["username"] != c.IdentityKey {
			t.Errorf("%s/%s listed with profile %v, want username %q", c.Provider, c.IdentityKey, c.Profile, c.IdentityKey)
		}
	}
}

// TestListEveryProvider: an empty Provider lists every channel.
func TestListEveryProvider(t *testing.T, factory Factory) {
	s := factory(t).Store
	save(t, s, "local", "username:alice")
	save(t, s, "github", "username:alice")
	save(t, s, "google", "email:carol@example.com")
	want := []string{"github/username:alice", "google/email:carol@example.com", "local/username:alice"}
	if got := names(list(t, s, "")); !equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

// TestDeleteRemovesOnlyTheNamedChannel: a delete removes the one channel,
// GetChannel then reports it missing, and the same identity under another
// provider stays.
func TestDeleteRemovesOnlyTheNamedChannel(t *testing.T, factory Factory) {
	s := factory(t).Store
	save(t, s, "local", "username:alice")
	save(t, s, "local", "username:bob")
	save(t, s, "github", "username:alice")
	if !del(t, s, "local", "username:alice") {
		t.Fatal("want Deleted true for a channel that exists")
	}
	if _, err := s.GetChannel(context.Background(), &accounts.GetChannelRequest{Provider: "local", IdentityKey: "username:alice"}); err == nil {
		t.Error("GetChannel found the deleted channel")
	}
	want := []string{"github/username:alice", "local/username:bob"}
	if got := names(list(t, s, "")); !equal(got, want) {
		t.Fatalf("want %v left, got %v", want, got)
	}
}

// TestDeleteIsRepeatable: deleting an absent channel, or one already
// deleted, returns Deleted false and no error.
func TestDeleteIsRepeatable(t *testing.T, factory Factory) {
	s := factory(t).Store
	if del(t, s, "local", "username:nobody") {
		t.Error("want Deleted false for a channel that never existed")
	}
	save(t, s, "local", "username:alice")
	if !del(t, s, "local", "username:alice") {
		t.Fatal("first delete: want Deleted true")
	}
	if del(t, s, "local", "username:alice") {
		t.Error("second delete: want Deleted false")
	}
}

// TestAnotherHandleSeesTheChanges: a channel saved and then deleted through
// one handle is listed, then not listed, through another, the way an
// operator's CLI and a running server share one store.
func TestAnotherHandleSeesTheChanges(t *testing.T, factory Factory) {
	b := factory(t)
	other := b.Reopen()
	save(t, b.Store, "local", "username:alice")
	if got := names(list(t, other, "local")); !equal(got, []string{"local/username:alice"}) {
		t.Fatalf("other handle: want alice listed, got %v", got)
	}
	if !del(t, other, "local", "username:alice") {
		t.Fatal("other handle: want Deleted true")
	}
	if got := list(t, b.Store, "local"); len(got) != 0 {
		t.Fatalf("first handle: want none after the other deleted, got %v", names(got))
	}
}

// TestListDuringDelete: one handle deletes channels while another lists.
// No listing fails, and none returns a half-read channel.
func TestListDuringDelete(t *testing.T, factory Factory) {
	b := factory(t)
	save(t, b.Store, "local", "username:keep")
	for i := 0; i < 20; i++ {
		save(t, b.Store, "local", fmt.Sprintf("username:gone%02d", i))
	}
	other := b.Reopen()

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 64)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 10; j++ {
				resp, err := b.Store.ListChannels(context.Background(), &accounts.ListChannelsRequest{Provider: "local"})
				if err != nil {
					errs <- err
					return
				}
				for _, c := range resp.Channels {
					if c.IdentityKey == "" || c.Provider != "local" {
						errs <- fmt.Errorf("listing returned a half-read channel %+v", c)
						return
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 20; i++ {
			if _, err := other.DeleteChannel(context.Background(), &accounts.DeleteChannelRequest{Provider: "local", IdentityKey: fmt.Sprintf("username:gone%02d", i)}); err != nil {
				errs <- err
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent call failed: %v", err)
	}
	if got := names(list(t, b.Store, "local")); !equal(got, []string{"local/username:keep"}) {
		t.Fatalf("want only keep left, got %v", got)
	}
}
