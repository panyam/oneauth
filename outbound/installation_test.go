package outbound_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/panyam/oneauth/outbound"
	"github.com/panyam/oneauth/outbound/githubtest"
	"golang.org/x/oauth2"
)

func newInstallation(t *testing.T, gh *githubtest.Server) *outbound.GitHubAppInstallation {
	t.Helper()
	src, err := outbound.NewGitHubAppInstallation(gh.AppID, gh.InstallationID, gh.AppKeyPEM())
	if err != nil {
		t.Fatalf("NewGitHubAppInstallation: %v", err)
	}
	src.BaseURL = gh.URL
	return src
}

// The fake checks the JWT's signature, iss and lifetime, so a token coming
// back means GitHub's checks pass.
// See: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
func TestInstallation_TokenWorksAtGitHub(t *testing.T) {
	gh := githubtest.New(t)
	src := newInstallation(t, gh)

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if !gh.ValidInstallationToken(tok.AccessToken) {
		t.Fatalf("fake doesn't recognise %q", tok.AccessToken)
	}
	resp, err := oauth2.NewClient(context.Background(), src).Get(gh.URL + "/installation/repositories")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("repositories: %d", resp.StatusCode)
	}
	c := gh.LastJWTClaims()
	iat, _ := c.GetIssuedAt()
	exp, _ := c.GetExpirationTime()
	if c["iss"] != gh.AppID || exp.Sub(iat.Time) > 10*time.Minute || time.Since(iat.Time) < 30*time.Second {
		t.Fatalf("claims: iss=%v iat=%v exp=%v", c["iss"], iat, exp)
	}
}

func TestInstallation_CachesUntilRefreshWindow(t *testing.T) {
	gh := githubtest.New(t)
	src := newInstallation(t, gh)
	now := time.Now()
	src.Now = func() time.Time { return now }
	gh.Now = src.Now

	first, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(50 * time.Minute)
	second, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	if gh.InstallationCalls() != 1 || second.AccessToken != first.AccessToken {
		t.Fatalf("within the TTL: calls=%d, same token=%v", gh.InstallationCalls(), second.AccessToken == first.AccessToken)
	}

	now = now.Add(6 * time.Minute) // 56 minutes in: inside the 5-minute window
	third, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	if gh.InstallationCalls() != 2 || third.AccessToken == first.AccessToken {
		t.Fatalf("inside the refresh window: calls=%d", gh.InstallationCalls())
	}
}

// oauth2.NewClient keeps a token until 10 seconds before Expiry, so the
// handed-out Expiry has to carry the refresh margin.
func TestInstallation_ExpiryCarriesRefreshMargin(t *testing.T) {
	gh := githubtest.New(t)
	src := newInstallation(t, gh)

	tok, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	real, ok := tok.Extra("expires_at").(time.Time)
	if !ok {
		t.Fatalf("expires_at extra missing")
	}
	if got := real.Sub(tok.Expiry); got != outbound.DefaultRefreshBefore {
		t.Fatalf("Expiry is %v before GitHub's, want %v", got, outbound.DefaultRefreshBefore)
	}
}

func TestInstallation_ConcurrentCallersShareOneFetch(t *testing.T) {
	gh := githubtest.New(t)
	src := newInstallation(t, gh)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := src.Token(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := gh.InstallationCalls(); n != 1 {
		t.Fatalf("installation exchanges = %d, want 1", n)
	}
}

// A refusal must not echo the JWT, which is valid for nine minutes.
// See: https://cwe.mitre.org/data/definitions/532.html
func TestInstallation_RefusalKeepsSecretsOutOfError(t *testing.T) {
	gh := githubtest.New(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	src := newInstallation(t, gh)
	src.Key = other
	appJWT, _ := src.AppJWT()

	_, err = src.Token()
	var ge *outbound.GitHubAPIError
	if !errors.As(err, &ge) || ge.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 GitHubAPIError, got %v", err)
	}
	if strings.Contains(err.Error(), appJWT[:40]) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("error leaks a secret: %v", err)
	}
}

func TestInstallation_UnknownInstallationIs404(t *testing.T) {
	gh := githubtest.New(t)
	src := newInstallation(t, gh)
	src.InstallationID = 99

	_, err := src.Token()
	var ge *outbound.GitHubAPIError
	if !errors.As(err, &ge) || ge.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %v", err)
	}
}

func TestInstallation_InvalidateForcesFetch(t *testing.T) {
	gh := githubtest.New(t)
	src := newInstallation(t, gh)
	if _, err := src.Token(); err != nil {
		t.Fatal(err)
	}
	src.Invalidate()
	if _, err := src.Token(); err != nil {
		t.Fatal(err)
	}
	if gh.InstallationCalls() != 2 {
		t.Fatalf("calls = %d, want 2", gh.InstallationCalls())
	}
}

// See: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func TestParseRSAPrivateKeyPEM(t *testing.T) {
	k2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(k2048)
	if _, err := outbound.ParseRSAPrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err != nil {
		t.Fatalf("PKCS#8: %v", err)
	}
	k1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	short := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k1024)})
	if _, err := outbound.ParseRSAPrivateKeyPEM(short); err == nil {
		t.Fatal("1024-bit key accepted")
	}
	if _, err := outbound.ParseRSAPrivateKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("non-PEM accepted")
	}
}
