//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/authcodetest"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/partest"
	"google.golang.org/api/option" //nolint:staticcheck // WithCredentialsFile is simpler for test use
)

// emulatorClient returns a Datastore client and a cleanup that empties
// kind in namespace, or skips when DATASTORE_PROJECT_ID is unset. make
// testds runs these on the emulator, as CI's gae job does.
func emulatorClient(t *testing.T, kind, namespace string) (*datastore.Client, func()) {
	t.Helper()
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE store tests")
	}
	ctx := context.Background()
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	client, err := datastore.NewClient(ctx, projectID, opts...)
	if err != nil {
		t.Fatalf("datastore client: %v", err)
	}
	cleanup := func() {
		keys, err := client.GetAll(ctx, datastore.NewQuery(kind).KeysOnly().Namespace(namespace), nil)
		if err == nil && len(keys) > 0 {
			_ = client.DeleteMulti(ctx, keys)
		}
	}
	t.Cleanup(func() { cleanup(); client.Close() })
	return client, cleanup
}

func TestGAEAuthorizationCodeStore_Contract(t *testing.T) {
	const ns = "oneauth-authcode-test"
	client, cleanup := emulatorClient(t, KindAuthorizationCode, ns)
	authcodetest.RunAll(t, func(t *testing.T) authcodetest.Backend {
		cleanup()
		return authcodetest.Backend{
			Store:  NewAuthorizationCodeStore(client, ns),
			Reopen: func() core.AuthorizationCodeStore { return NewAuthorizationCodeStore(client, ns) },
		}
	})
}

func TestGAEPushedAuthorizationRequestStore_Contract(t *testing.T) {
	const ns = "oneauth-par-test"
	client, cleanup := emulatorClient(t, KindPushedAuthorizationRequest, ns)
	partest.RunAll(t, func(t *testing.T) partest.Backend {
		cleanup()
		return partest.Backend{
			Store:  NewPushedAuthorizationRequestStore(client, ns),
			Reopen: func() core.PushedAuthorizationRequestStore { return NewPushedAuthorizationRequestStore(client, ns) },
		}
	})
}

// A copy of the datastore must hold neither a code nor a request_uri, in
// a key name or in a property.
// See: https://cwe.mitre.org/data/definitions/312.html
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.14
func TestGAEAuthorizationCodeAndPushedRequest_PlaintextNeverStored(t *testing.T) {
	const ns = "oneauth-atrest-test"
	client, _ := emulatorClient(t, KindAuthorizationCode, ns)
	_, cleanPAR := emulatorClient(t, KindPushedAuthorizationRequest, ns)
	t.Cleanup(cleanPAR)
	ctx := context.Background()
	code := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
	codes := NewAuthorizationCodeStore(client, ns)
	if _, err := codes.CreateAuthorizationCode(ctx, &core.CreateAuthorizationCodeRequest{Code: &core.AuthorizationCode{
		Code: code, ClientID: "c", RedirectURI: "https://app/cb", Subject: "u", ExpiresAt: time.Now().Add(time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	ref := "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	pars := NewPushedAuthorizationRequestStore(client, ns)
	if _, err := pars.CreatePushedAuthorizationRequest(ctx, &core.CreatePushedAuthorizationRequestRequest{Request: &core.PushedAuthorizationRequest{
		RequestURI: core.PushedRequestURIPrefix + ref, ClientID: "c", Payload: url.Values{"scope": {"openid"}}, ExpiresAt: time.Now().Add(time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}

	var ce []AuthorizationCodeEntity
	ckeys, err := client.GetAll(ctx, datastore.NewQuery(KindAuthorizationCode).Namespace(ns), &ce)
	if err != nil || len(ckeys) != 1 {
		t.Fatalf("code entities: %d, %v", len(ckeys), err)
	}
	if strings.Contains(ckeys[0].Name, code) || strings.Contains(string(ce[0].Record), code) {
		t.Fatal("the code is stored in plaintext")
	}
	var pe []PushedAuthorizationRequestEntity
	pkeys, err := client.GetAll(ctx, datastore.NewQuery(KindPushedAuthorizationRequest).Namespace(ns), &pe)
	if err != nil || len(pkeys) != 1 {
		t.Fatalf("pushed entities: %d, %v", len(pkeys), err)
	}
	if strings.Contains(pkeys[0].Name, ref) || strings.Contains(string(pe[0].Record), ref) {
		t.Fatal("the request_uri is stored in plaintext")
	}
}
