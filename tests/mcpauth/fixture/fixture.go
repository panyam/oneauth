// Package fixture is what the two MCP server fixtures in tests/mcpauth/cmd
// share: the tools the MCP server-auth conformance scenarios call, and the
// tokens they need (issue 495).
//
// oneauth-server is the authorization server. The valid tokens come from
// its token endpoint through client_credentials. The expired, wrong-audience
// and wrong-issuer tokens take a valid token's claims, change one, and
// re-sign with the server's own key and kid, so each one passes signature
// verification and fails exactly one claim check (RFC 7519 §4.1).
package fixture

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/utils"
)

// Tool names and the scope each needs, as the conformance scenarios expect
// them. Echo needs a valid token and no scope.
const (
	EchoTool  = "echo"
	WriteTool = "write-tool"
	AdminTool = "admin-tool"
)

// Scopes are the scopes the fixtures advertise and the AS issues.
var Scopes = []string{"read", "write", "admin"}

// ToolScopes maps each scope-gated tool to the scope it requires.
var ToolScopes = map[string]string{WriteTool: "write", AdminTool: "admin"}

// Config locates the AS and the MCP endpoint.
type Config struct {
	// ASURL is oneauth-server's issuer and base URL.
	ASURL string
	// MCPURL is the MCP endpoint, which is also the resource identifier
	// and the tokens' aud.
	MCPURL string
	// KeyPath is the PEM private key oneauth-server signs with
	// (jwt.private_key_path).
	KeyPath string
	// IdPKeyPath is the PEM private key of the upstream IdP the AS trusts
	// (trusted_assertion_issuers), and IdPIssuer its iss. With both set,
	// Bootstrap also mints an assertion from that IdP. Empty skips it.
	IdPKeyPath string
	IdPIssuer  string
}

// Tokens are what GET /demo/bootstrap returns. The field names are the ones
// the conformance scripts read.
type Tokens struct {
	MCPURL         string `json:"mcp_url"`
	TokRead        string `json:"tok_read"`
	TokReadWrite   string `json:"tok_read_write"`
	TokAll         string `json:"tok_all"`
	TokExpired     string `json:"tok_expired"`
	TokWrongAud    string `json:"tok_wrong_audience"`
	TokWrongIssuer string `json:"tok_wrong_issuer"`
	// TokUpstreamAssertion is a JWT from the trusted upstream IdP, which
	// the AS accepts as a jwt-bearer assertion or token-exchange subject
	// token. Empty without Config.IdPKeyPath.
	TokUpstreamAssertion string `json:"tok_upstream_assertion,omitempty"`
}

// Bootstrap registers a client with the AS through open DCR, mints the
// three valid tokens with client_credentials for the MCP endpoint as their
// RFC 8707 resource, and derives the three bad ones from the first.
func Bootstrap(ctx context.Context, hc *http.Client, cfg Config) (*Tokens, error) {
	clientID, secret, err := register(ctx, hc, cfg.ASURL)
	if err != nil {
		return nil, err
	}
	t := &Tokens{MCPURL: cfg.MCPURL}
	for _, x := range []struct {
		dst   *string
		scope string
	}{{&t.TokRead, "read"}, {&t.TokReadWrite, "read write"}, {&t.TokAll, "read write admin"}} {
		if *x.dst, err = clientCredentials(ctx, hc, cfg.ASURL, clientID, secret, x.scope, cfg.MCPURL); err != nil {
			return nil, err
		}
	}
	key, alg, err := LoadKey(cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	t.TokExpired, t.TokWrongAud, t.TokWrongIssuer, err = BadTokens(t.TokRead, key, alg)
	if err != nil {
		return nil, err
	}
	if cfg.IdPKeyPath != "" && cfg.IdPIssuer != "" {
		idpKey, idpAlg, err := LoadKey(cfg.IdPKeyPath)
		if err != nil {
			return nil, fmt.Errorf("upstream IdP key: %w", err)
		}
		if t.TokUpstreamAssertion, err = UpstreamAssertion(idpKey, idpAlg, cfg.IdPIssuer, cfg.ASURL, "alice"); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// UpstreamAssertion is a JWT from the upstream IdP issuer about subject,
// addressed to the AS at asURL (RFC 7523 §3), valid for ten minutes. It has
// a fresh jti, since the AS may refuse a repeated one.
func UpstreamAssertion(key crypto.Signer, alg, issuer, asURL, subject string) (string, error) {
	now := time.Now()
	return sign(map[string]any{"typ": "JWT"}, jwt.MapClaims{
		"iss": issuer, "sub": subject, "aud": asURL, "jti": rand.Text(),
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}, key, alg)
}

// BadTokens derives the expired, wrong-audience and wrong-issuer variants of
// valid, each signed with key under valid's kid.
func BadTokens(valid string, key crypto.Signer, alg string) (expired, wrongAud, wrongIss string, err error) {
	header, claims, err := parse(valid)
	if err != nil {
		return "", "", "", err
	}
	past := time.Now().Add(-time.Hour)
	variants := []func(jwt.MapClaims){
		func(c jwt.MapClaims) { c["iat"], c["exp"] = past.Add(-time.Hour).Unix(), past.Unix() },
		func(c jwt.MapClaims) { c["aud"] = "https://another-resource.example/mcp" },
		func(c jwt.MapClaims) { c["iss"] = "https://another-issuer.example" },
	}
	out := make([]string, len(variants))
	for i, mutate := range variants {
		c := jwt.MapClaims{}
		for k, v := range claims {
			c[k] = v
		}
		mutate(c)
		if out[i], err = sign(header, c, key, alg); err != nil {
			return "", "", "", err
		}
	}
	return out[0], out[1], out[2], nil
}

// LoadKey reads the PEM private key at path and the JWS algorithm it signs
// with.
func LoadKey(path string) (crypto.Signer, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read signing key: %w", err)
	}
	key, err := utils.ParsePrivateKeyPEM(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse signing key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, "", fmt.Errorf("signing key is %T, not a crypto.Signer", key)
	}
	switch k := signer.(type) {
	case *rsa.PrivateKey:
		return k, "RS256", nil
	case *ecdsa.PrivateKey:
		return k, "ES256", nil
	}
	return nil, "", fmt.Errorf("signing key is %T; want RSA or ECDSA P-256", signer)
}

// BootstrapHandler serves t as GET /demo/bootstrap.
func BootstrapHandler(t *Tokens) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(t)
	})
}

func parse(token string) (map[string]any, jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	tok, _, err := jwt.NewParser().ParseUnverified(token, claims)
	if err != nil {
		return nil, nil, fmt.Errorf("parse token: %w", err)
	}
	return tok.Header, claims, nil
}

func sign(header map[string]any, claims jwt.MapClaims, key crypto.Signer, alg string) (string, error) {
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("unknown alg %q", alg)
	}
	tok := jwt.NewWithClaims(method, claims)
	for k, v := range header {
		if k != "alg" {
			tok.Header[k] = v
		}
	}
	return tok.SignedString(key)
}

func register(ctx context.Context, hc *http.Client, asURL string) (string, string, error) {
	body := `{"client_name":"mcp-auth-conformance","grant_types":["client_credentials"],"scope":"read write admin"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, asURL+"/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := doJSON(hc, req, http.StatusCreated, &out); err != nil {
		return "", "", fmt.Errorf("register client: %w", err)
	}
	return out.ClientID, out.ClientSecret, nil
}

// clientCredentials mints a token for resource (RFC 8707), which the AS
// stamps as its aud.
func clientCredentials(ctx context.Context, hc *http.Client, asURL, clientID, secret, scope, resource string) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}, "resource": {resource}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, asURL+"/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := doJSON(hc, req, http.StatusOK, &out); err != nil {
		return "", fmt.Errorf("client_credentials %q: %w", scope, err)
	}
	return out.AccessToken, nil
}

func doJSON(hc *http.Client, req *http.Request, want int, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	return json.Unmarshal(raw, out)
}
