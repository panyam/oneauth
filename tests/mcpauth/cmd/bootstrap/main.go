// Command bootstrap mints the MCP auth conformance tokens against a running
// oneauth-server and prints them as the JSON /demo/bootstrap serves (issue
// 521). The TypeScript fixture reads its output, so all three fixtures get
// their tokens from the same code in package fixture.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/panyam/oneauth/tests/mcpauth/fixture"
)

func main() {
	asURL := flag.String("as", "http://localhost:18200", "oneauth-server issuer URL")
	mcpURL := flag.String("mcp-url", "http://localhost:18300/mcp", "the MCP endpoint's public URL, the tokens' resource")
	keyPath := flag.String("key", "", "oneauth-server's signing key, for the bad-claim tokens")
	idpKey := flag.String("idp-key", "", "the trusted upstream IdP's signing key")
	idpIssuer := flag.String("idp-issuer", "", "the trusted upstream IdP's iss")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tokens, err := fixture.Bootstrap(ctx, http.DefaultClient, fixture.Config{
		ASURL: *asURL, MCPURL: *mcpURL, KeyPath: *keyPath, IdPKeyPath: *idpKey, IdPIssuer: *idpIssuer,
	})
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(tokens); err != nil {
		log.Fatal(err)
	}
}
