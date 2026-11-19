package fs_test

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/authcodetest"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/partest"
	"github.com/panyam/oneauth/stores/fs"
)

func TestFSAuthorizationCodeStore_Contract(t *testing.T) {
	authcodetest.RunAll(t, func(t *testing.T) authcodetest.Backend {
		dir := t.TempDir()
		return authcodetest.Backend{
			Store:  fs.NewFSAuthorizationCodeStore(dir),
			Reopen: func() core.AuthorizationCodeStore { return fs.NewFSAuthorizationCodeStore(dir) },
		}
	})
}

func TestFSPushedAuthorizationRequestStore_Contract(t *testing.T) {
	partest.RunAll(t, func(t *testing.T) partest.Backend {
		dir := t.TempDir()
		return partest.Backend{
			Store:  fs.NewFSPushedAuthorizationRequestStore(dir),
			Reopen: func() core.PushedAuthorizationRequestStore { return fs.NewFSPushedAuthorizationRequestStore(dir) },
		}
	})
}

// requireNotOnDisk fails if any file under dir holds secret, in its name
// or its contents.
func requireNotOnDisk(t *testing.T, dir, secret string) {
	t.Helper()
	files := 0
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		files++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(p, secret) || strings.Contains(string(b), secret) {
			t.Errorf("%s holds the plaintext value", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("nothing was written")
	}
}

// A copy of the storage directory must not hold a redeemable code, even
// after it is used and tokens are recorded on it.
// See: https://cwe.mitre.org/data/definitions/312.html
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.14
func TestFSAuthorizationCodeStore_CodeNeverOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := fs.NewFSAuthorizationCodeStore(dir)
	ctx := context.Background()
	code := "d41c8cd98f00b204e9800998ecf8427e1f2a3b4c5d6e7f8091a2b3c4d5e6f708"
	if _, err := s.CreateAuthorizationCode(ctx, &core.CreateAuthorizationCodeRequest{Code: &core.AuthorizationCode{
		Code: code, ClientID: "c", RedirectURI: "https://app/cb", Subject: "u", ExpiresAt: time.Now().Add(time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, &core.ConsumeAuthorizationCodeRequest{Code: code}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordAuthorizationCodeTokens(ctx, &core.RecordAuthorizationCodeTokensRequest{Code: code, TokenID: "jti", TokenExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	requireNotOnDisk(t, dir, code)
}

// See: https://cwe.mitre.org/data/definitions/312.html
// See: https://www.rfc-editor.org/rfc/rfc9126#section-2.2
func TestFSPushedAuthorizationRequestStore_RequestURINeverOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := fs.NewFSPushedAuthorizationRequestStore(dir)
	ctx := context.Background()
	ref := "9b74c9897bac770ffc029102a200c5de"
	if _, err := s.CreatePushedAuthorizationRequest(ctx, &core.CreatePushedAuthorizationRequestRequest{Request: &core.PushedAuthorizationRequest{
		RequestURI: core.PushedRequestURIPrefix + ref, ClientID: "c", Payload: url.Values{"scope": {"openid"}}, ExpiresAt: time.Now().Add(time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumePushedAuthorizationRequest(ctx, &core.ConsumePushedAuthorizationRequestRequest{RequestURI: core.PushedRequestURIPrefix + ref}); err != nil {
		t.Fatal(err)
	}
	requireNotOnDisk(t, dir, ref)
}
