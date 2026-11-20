// Command gosdk-fixture is an MCP server built on the official Go SDK
// (github.com/modelcontextprotocol/go-sdk) with oneauth as its whole auth
// layer, for the MCP server-auth conformance suite (issue 495).
//
// The SDK only carries JSON-RPC. oneauth's APIMiddleware validates every
// request's token against oneauth-server's JWKS, issuer and audience, and
// writes each 401 and 403 with its WWW-Authenticate challenge. oneauth's
// ProtectedResourceMetadata serves RFC 9728 discovery. So a check that fails
// here is oneauth's to fix.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/tests/mcpauth/fixture"
)

func main() {
	addr := flag.String("addr", ":18300", "listen address")
	asURL := flag.String("as", "http://localhost:18200", "oneauth-server issuer URL")
	mcpURL := flag.String("mcp-url", "http://localhost:18300/mcp", "the MCP endpoint's public URL, which is the tokens' aud")
	keyPath := flag.String("key", "", "oneauth-server's signing key, for the bad-claim tokens")
	idpKey := flag.String("idp-key", "", "the trusted upstream IdP's signing key, for an assertion it issues")
	idpIssuer := flag.String("idp-issuer", "", "the trusted upstream IdP's iss")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tokens, err := fixture.Bootstrap(ctx, http.DefaultClient, fixture.Config{ASURL: *asURL, MCPURL: *mcpURL, KeyPath: *keyPath, IdPKeyPath: *idpKey, IdPIssuer: *idpIssuer})
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	jwks := keys.NewJWKSKeyStore(*asURL + "/.well-known/jwks.json")
	if err := jwks.Start(); err != nil {
		log.Fatalf("JWKS: %v", err)
	}
	defer jwks.Stop()
	base, mcpPath := splitURL(*mcpURL)
	mw := &apiauth.APIMiddleware{
		KeyStore:            jwks,
		JWTIssuer:           *asURL,
		JWTAudience:         *mcpURL,
		ResourceMetadataURL: base + "/.well-known/oauth-protected-resource" + mcpPath,
	}

	mux := http.NewServeMux()
	apiauth.MountProtectedResource(mux, &apiauth.ProtectedResourceMetadata{
		Resource:               *mcpURL,
		AuthorizationServers:   []string{*asURL},
		ScopesSupported:        fixture.Scopes,
		BearerMethodsSupported: []string{"header"},
	}, true, mcpPath)
	mux.Handle("GET /demo/bootstrap", fixture.BootstrapHandler(tokens))
	mux.Handle(mcpPath, scopeGate(mw, mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return newServer() }, nil)))

	log.Printf("go-sdk MCP fixture on %s, AS %s", *mcpURL, *asURL)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

type echoIn struct {
	Message string `json:"message,omitempty"`
}

func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "oneauth-gosdk-fixture", Version: "1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: fixture.EchoTool, Description: "Echoes its input; needs a valid token and no scope"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			return text("echo: " + in.Message), nil, nil
		})
	for name, scope := range fixture.ToolScopes {
		mcp.AddTool(s, &mcp.Tool{Name: name, Description: "Needs the " + scope + " scope"},
			func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
				return text(name + " ok"), nil, nil
			})
	}
	return s
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// scopeGate sends every request through mw. A tools/call for a scope-gated
// tool goes through mw.RequireScopes instead, so oneauth answers a token
// without that scope with 403 insufficient_scope and the scope it needs
// (RFC 6750 §3.1). It reads the JSON-RPC body to find the tool, then
// restores it for the SDK.
func scopeGate(mw *apiauth.APIMiddleware, next http.Handler) http.Handler {
	validated := mw.ValidateToken(next)
	gated := map[string]http.Handler{}
	for name, scope := range fixture.ToolScopes {
		gated[name] = mw.RequireScopes(scope)(next)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "could not read the request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var msg struct {
				Method string `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			if json.Unmarshal(body, &msg) == nil && msg.Method == "tools/call" {
				if h, ok := gated[msg.Params.Name]; ok {
					h.ServeHTTP(w, r)
					return
				}
			}
		}
		validated.ServeHTTP(w, r)
	})
}

// splitURL splits http://host:port/path into the origin and the path.
func splitURL(u string) (base, path string) {
	rest := u[strings.Index(u, "://")+3:]
	if i := strings.Index(rest, "/"); i >= 0 {
		return u[:len(u)-len(rest)+i], rest[i:]
	}
	return u, "/"
}
