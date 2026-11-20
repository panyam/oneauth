// Command mcpkit-fixture is an MCP server built on mcpkit
// (github.com/panyam/mcpkit) with its ext/auth layer, for the MCP
// server-auth conformance suite (issue 495).
//
// oneauth-server is the authorization server. mcpkit's ext/auth validates
// tokens against its JWKS, writes the 401 and 403 challenges, and serves
// RFC 9728 discovery. So a check that fails only here, and passes against
// gosdk-fixture, is most likely mcpkit's to fix.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/panyam/mcpkit/core"
	"github.com/panyam/mcpkit/ext/auth"
	"github.com/panyam/mcpkit/server"
	"github.com/panyam/oneauth/tests/mcpauth/fixture"
)

func main() {
	addr := flag.String("addr", ":18300", "listen address")
	asURL := flag.String("as", "http://localhost:18200", "oneauth-server issuer URL")
	mcpURL := flag.String("mcp-url", "http://localhost:18300/mcp", "the MCP endpoint's public URL, which is the tokens' aud")
	keyPath := flag.String("key", "", "oneauth-server's signing key, for the bad-claim tokens")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tokens, err := fixture.Bootstrap(ctx, http.DefaultClient, fixture.Config{ASURL: *asURL, MCPURL: *mcpURL, KeyPath: *keyPath})
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	mcpPath := (*mcpURL)[strings.Index(*mcpURL, "://")+3:]
	mcpPath = mcpPath[strings.Index(mcpPath, "/"):]
	base := strings.TrimSuffix(*mcpURL, mcpPath)
	validator := auth.NewJWTValidator(auth.JWTConfig{
		JWKSURL:             *asURL + "/.well-known/jwks.json",
		Issuer:              *asURL,
		Audience:            *mcpURL,
		ResourceMetadataURL: base + "/.well-known/oauth-protected-resource" + mcpPath,
		AllScopes:           fixture.Scopes,
	})
	validator.Start()

	srv := server.NewServer(core.Implementation{Name: "oneauth-mcpkit-fixture", Version: "1.0"},
		server.WithListen(*addr),
		server.WithAuth(validator),
		server.WithPublicMethods("initialize", "notifications/initialized", "tools/list", "ping"),
	)
	srv.Register(core.TextTool[echoIn](fixture.EchoTool, "Echoes its input; needs a valid token and no scope",
		func(_ core.ToolContext, in echoIn) (string, error) { return "echo: " + in.Message, nil }))
	for name, scope := range fixture.ToolScopes {
		srv.Register(core.TextTool[struct{}](name, "Needs the "+scope+" scope",
			func(core.ToolContext, struct{}) (string, error) { return name + " ok", nil },
			core.WithToolRequiredScopes(scope)))
	}
	srv.UseMiddleware(auth.NewToolScopeMiddleware(srv.Registry()))

	log.Printf("mcpkit MCP fixture on %s, AS %s", *mcpURL, *asURL)
	// ListenAndServe, not Handler: only it applies WithMux's routes.
	log.Fatal(srv.ListenAndServe(
		server.WithPrefix(mcpPath),
		server.WithStreamableHTTP(true),
		server.WithSSE(false),
		server.WithMux(func(m *http.ServeMux) {
			m.Handle("GET /demo/bootstrap", fixture.BootstrapHandler(tokens))
			auth.MountAuth(m, auth.AuthConfig{
				ResourceURI:          *mcpURL,
				AuthorizationServers: []string{*asURL},
				ScopesSupported:      fixture.Scopes,
				MCPPath:              mcpPath,
				Validator:            validator,
			})
		}),
	))
}

type echoIn struct {
	Message string `json:"message,omitempty"`
}
