package cmd

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/panyam/oneauth/client"
	"github.com/spf13/cobra"
)

// tokenFlags holds the persistent flags shared by every `oneauth token`
// subcommand. The parent command parses them via PersistentFlags so each
// subcommand inherits the same flag values without redefining them.
type tokenFlags struct {
	format string
}

// newTokenCommand builds `oneauth token`, the parent of the four grant
// subcommands. The grant-specific flags live on the children — only
// flags that apply to every grant (format) live here.
func newTokenCommand() *cobra.Command {
	tf := &tokenFlags{}
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Acquire OAuth 2.0 access tokens",
		Long: `Acquire OAuth 2.0 access tokens from any RFC 8414 / OIDC-compliant
authorization server. Each subcommand handles one grant type.`,
	}
	cmd.PersistentFlags().StringVar(&tf.format, "format", "json",
		`output format: "json" | "bash" | "access-token-only"`)

	cmd.AddCommand(
		newBrowserCommand(tf),
		newClientCredentialsCommand(tf),
		newPasswordCommand(tf),
		newRefreshCommand(tf),
	)
	return cmd
}

// newAuthClient builds an AuthClient with AS metadata discovered from
// the supplied issuer URL.
//
// The CredentialStore is intentionally nil — the CLI prints; the caller
// persists. AuthClient handles a nil store via its built-in no-op
// substitute (see client.NewAuthClient).
func newAuthClient(issuerURL string) (*client.AuthClient, *client.ASMetadata, error) {
	if issuerURL == "" {
		return nil, nil, fmt.Errorf("issuer URL is required")
	}
	httpClient := http.DefaultClient

	meta, err := client.DiscoverAS(issuerURL, client.WithHTTPClientForDiscovery(httpClient))
	if err != nil {
		return nil, nil, fmt.Errorf("discovery (%s): %w", issuerURL, err)
	}

	ac := client.NewAuthClient(issuerURL, nil,
		client.WithASMetadata(meta),
		client.WithHTTPClient(httpClient),
	)
	return ac, meta, nil
}

// splitScopes turns the user-supplied space-delimited `--scopes` value
// into the []string the SDK methods accept. Empty input yields nil so
// the SDK omits the `scope` form value entirely.
func splitScopes(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// readStdinSecret reads stdin for password / secret / refresh-token
// *-stdin flags. Trims a single trailing newline (covers both
// `echo X | oneauth ...` and `oneauth ... < file` shapes) but otherwise
// preserves whitespace — secrets may legitimately contain it.
func readStdinSecret() (string, error) {
	buf, err := readAllStdin(os.Stdin)
	if err != nil {
		return "", err
	}
	s := string(buf)
	s = strings.TrimRight(s, "\r\n")
	return s, nil
}
