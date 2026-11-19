package outbound_test

// Live smoke tests against real GitHub. Skipped unless ONEAUTH_GH_LIVE=1,
// so plain `go test` and CI never call GitHub. `make testgh` runs them.
//
// Environment:
//
//	ONEAUTH_GH_LIVE=1              turn the tests on
//	ONEAUTH_GH_TEST_REPOS          owner/repo,owner/repo (default panyam/oneauth-smoke-a,-b)
//	ONEAUTH_GH_PAT_REF             SecretRef for a PAT (default env:GH_PERSONAL_TOKEN)
//	ONEAUTH_GH_APP_ID              GitHub App ID           } App checks skip
//	ONEAUTH_GH_INSTALLATION_ID     its installation ID     } without these
//	ONEAUTH_GH_APP_KEY_FILE        path to its private key }
//	ONEAUTH_GH_LIVE_DEVICE=1       run the interactive device-flow check, which
//	ONEAUTH_GH_CLIENT_ID           also needs the App's client ID and secret
//	ONEAUTH_GH_CLIENT_SECRET
//
// The repos' READMEs carry a line "oneauth-smoke-marker: <suffix>", where
// <suffix> is what follows "oneauth-smoke-" in the repo name. For repos
// named otherwise the check is that the README is readable and non-empty.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/outbound"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

func liveOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("ONEAUTH_GH_LIVE") != "1" {
		t.Skip("ONEAUTH_GH_LIVE not set; skipping live GitHub test")
	}
}

func liveRepos(t *testing.T) []string {
	t.Helper()
	v := os.Getenv("ONEAUTH_GH_TEST_REPOS")
	if v == "" {
		v = "panyam/oneauth-smoke-a,panyam/oneauth-smoke-b"
	}
	repos := strings.Split(v, ",")
	if len(repos) < 2 {
		t.Fatalf("ONEAUTH_GH_TEST_REPOS needs two repos, got %q", v)
	}
	return repos
}

// liveApp builds the App installation source, or skips when the App's
// env vars are missing.
func liveApp(t *testing.T) *outbound.GitHubAppInstallation {
	t.Helper()
	appID, instID, keyFile := os.Getenv("ONEAUTH_GH_APP_ID"), os.Getenv("ONEAUTH_GH_INSTALLATION_ID"), os.Getenv("ONEAUTH_GH_APP_KEY_FILE")
	if appID == "" || instID == "" || keyFile == "" {
		t.Skip("ONEAUTH_GH_APP_ID / _INSTALLATION_ID / _APP_KEY_FILE not set; skipping App check")
	}
	id, err := strconv.ParseInt(instID, 10, 64)
	if err != nil {
		t.Fatalf("ONEAUTH_GH_INSTALLATION_ID: %v", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read App key: %v", err)
	}
	src, err := outbound.NewGitHubAppInstallation(appID, id, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	src.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	return src
}

// readREADME fetches repo's README as raw text through client.
func readREADME(t *testing.T, client *http.Client, repo string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, outbound.DefaultGitHubAPI+"/repos/"+repo+"/readme", nil)
	req.Header.Set("Accept", "application/vnd.github.raw+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s README: %v", repo, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b)
}

func wantReadable(t *testing.T, client *http.Client, repo string) {
	t.Helper()
	status, body := readREADME(t, client, repo)
	if status != http.StatusOK {
		t.Fatalf("%s README: status %d", repo, status)
	}
	name := repo[strings.LastIndex(repo, "/")+1:]
	if suffix, ok := strings.CutPrefix(name, "oneauth-smoke-"); ok {
		if !strings.Contains(body, "oneauth-smoke-marker: "+suffix) {
			t.Fatalf("%s README lacks its marker line", repo)
		}
	} else if strings.TrimSpace(body) == "" {
		t.Fatalf("%s README is empty", repo)
	}
}

// Check 1: a PAT read through a SecretRef reads both repos.
func TestLiveGitHub_StaticPATReadsRepos(t *testing.T) {
	liveOnly(t)
	ref := os.Getenv("ONEAUTH_GH_PAT_REF")
	if ref == "" {
		ref = "env:GH_PERSONAL_TOKEN"
	}
	src, err := outbound.NewStatic(ref)
	if err != nil {
		t.Fatalf("NewStatic(%s): %v", ref, err)
	}
	client := oauth2.NewClient(context.Background(), src)
	for _, repo := range liveRepos(t) {
		wantReadable(t, client, repo)
	}
}

// Check 5: GitHub's refusals come back as GitHubAPIError with GitHub's
// message. With no App configured, a made-up App ID gets 404 "Integration
// not found", since GitHub looks the App up before checking the signature.
// With a real App, a JWT signed by the wrong key gets 401.
func TestLiveGitHub_RefusalsCarryGitHubsMessage(t *testing.T) {
	liveOnly(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	appID, want := os.Getenv("ONEAUTH_GH_APP_ID"), http.StatusUnauthorized
	if appID == "" {
		appID, want = "1", http.StatusNotFound
	}
	inst := int64(1)
	if v, err := strconv.ParseInt(os.Getenv("ONEAUTH_GH_INSTALLATION_ID"), 10, 64); err == nil {
		inst = v
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	src, err := outbound.NewGitHubAppInstallation(appID, inst, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	src.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	_, err = src.Token()
	var ge *outbound.GitHubAPIError
	if !errors.As(err, &ge) || ge.StatusCode != want || ge.Message == "" {
		t.Fatalf("want a %d GitHubAPIError with GitHub's message, got %v", want, err)
	}
	t.Logf("GitHub's refusal: %v", err)
}

// Checks 2 and 4: the App's installation token lists and reads both repos,
// is cached, and Invalidate fetches a new one.
func TestLiveGitHub_AppInstallationReadsRepos(t *testing.T) {
	liveOnly(t)
	src := liveApp(t)
	first, err := src.Token()
	if err != nil {
		t.Fatalf("installation token: %v", err)
	}
	client := oauth2.NewClient(context.Background(), src)

	resp, err := client.Get(outbound.DefaultGitHubAPI + "/installation/repositories")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("installation/repositories: %d", resp.StatusCode)
	}
	for _, repo := range liveRepos(t) {
		if !strings.Contains(string(b), `"full_name":"`+repo+`"`) {
			t.Errorf("installation doesn't list %s; install the App on it", repo)
		}
		wantReadable(t, client, repo)
	}

	again, err := src.Token()
	if err != nil || again.AccessToken != first.AccessToken {
		t.Fatalf("second Token() fetched a new token (err %v)", err)
	}
	exp, _ := first.Extra("expires_at").(time.Time)
	if d := time.Until(exp); d < 50*time.Minute || d > 61*time.Minute {
		t.Errorf("GitHub's expires_at is %v away, expected about an hour", d)
	}
	src.Invalidate()
	fresh, err := src.Token()
	if err != nil || fresh.AccessToken == first.AccessToken {
		t.Fatalf("Invalidate didn't fetch a new token (err %v)", err)
	}
}

// Check 3: a token narrowed to one repo reads it and can't see the other.
func TestLiveGitHub_AppTokenNarrowedToOneRepo(t *testing.T) {
	liveOnly(t)
	src := liveApp(t)
	repos := liveRepos(t)
	src.Repositories = []string{repos[0][strings.LastIndex(repos[0], "/")+1:]}
	src.Permissions = map[string]string{"contents": "read"}
	client := oauth2.NewClient(context.Background(), src)

	wantReadable(t, client, repos[0])
	if status, _ := readREADME(t, client, repos[1]); status != http.StatusNotFound {
		t.Fatalf("narrowed token read %s: status %d, want 404", repos[1], status)
	}
}

// Check 6, interactive: a person's token from device flow is refreshed by
// StoredUserToken (and its refresh token rotates), then revoked. Finally
// it revokes the dead token again and logs what GitHub answers, which
// GitHub's docs don't say.
func TestLiveGitHub_DeviceFlowRefreshAndRevoke(t *testing.T) {
	liveOnly(t)
	if os.Getenv("ONEAUTH_GH_LIVE_DEVICE") != "1" {
		t.Skip("ONEAUTH_GH_LIVE_DEVICE not set; skipping interactive device-flow check")
	}
	clientID, secret := os.Getenv("ONEAUTH_GH_CLIENT_ID"), os.Getenv("ONEAUTH_GH_CLIENT_SECRET")
	if clientID == "" || secret == "" {
		t.Fatal("ONEAUTH_GH_CLIENT_ID and ONEAUTH_GH_CLIENT_SECRET are required")
	}
	cfg := &oauth2.Config{ClientID: clientID, ClientSecret: secret, Endpoint: endpoints.GitHub}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	da, err := cfg.DeviceAuth(ctx)
	if err != nil {
		t.Fatalf("device code: %v (is Device Flow enabled on the App?)", err)
	}
	fmt.Fprintf(os.Stderr, "\n>>> Open %s and enter %s (waiting up to 5 minutes)\n\n", da.VerificationURI, da.UserCode)
	tok, err := cfg.DeviceAccessToken(ctx, da)
	if err != nil {
		t.Fatalf("device token: %v", err)
	}
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token: turn on 'Expire user authorization tokens' in the App settings")
	}
	login := liveUser(t, tok.AccessToken)
	t.Logf("device flow signed in as %s; token expires %v", login, tok.Expiry)

	master := make([]byte, 32)
	_, _ = rand.Read(master)
	store := outbound.NewMemoryUserTokenStore()
	u, err := outbound.NewUserTokens("github", store, hex.EncodeToString(master), cfg)
	if err != nil {
		t.Fatal(err)
	}
	stale := *tok
	stale.Expiry = time.Now().Add(-time.Minute) // force a refresh
	if err := u.Save(ctx, login, &stale); err != nil {
		t.Fatal(err)
	}
	refreshed, err := u.TokenSource(login).TokenContext(ctx)
	if err != nil {
		t.Fatalf("refresh against GitHub: %v", err)
	}
	if refreshed.AccessToken == tok.AccessToken {
		t.Fatal("refresh returned the same access token")
	}
	if got := liveUser(t, refreshed.AccessToken); got != login {
		t.Fatalf("refreshed token is for %s, want %s", got, login)
	}
	rec, _ := store.GetUserToken(ctx, &outbound.GetUserTokenRequest{Provider: "github", Subject: login})
	t.Logf("refresh wrote version %d; old access token still live: %v", rec.Record.Version, liveUserStatus(t, tok.AccessToken) == http.StatusOK)

	revoker := &outbound.GitHubRevoker{ClientID: clientID, ClientSecret: secret}
	u.Revoker = revoker
	if err := u.Revoke(ctx, login); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if s := liveUserStatus(t, refreshed.AccessToken); s != http.StatusUnauthorized {
		t.Fatalf("revoked token: /user status %d, want 401", s)
	}
	_, err = revoker.RevokeToken(ctx, &outbound.RevokeTokenRequest{Token: refreshed})
	t.Logf("revoking an already-revoked token answers: %v (issue 468)", err)
}

func liveUserStatus(t *testing.T, accessToken string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, outbound.DefaultGitHubAPI+"/user", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func liveUser(t *testing.T, accessToken string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, outbound.DefaultGitHubAPI+"/user", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/user: status %d", resp.StatusCode)
	}
	i := strings.Index(string(b), `"login":"`)
	if i < 0 {
		t.Fatalf("/user: no login in response")
	}
	rest := string(b)[i+len(`"login":"`):]
	return rest[:strings.Index(rest, `"`)]
}
