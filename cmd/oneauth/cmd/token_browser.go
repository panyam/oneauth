package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/spf13/cobra"
)

// browserFlags collects the flag set specific to the browser
// (authorization code + PKCE, RFC 8252 + 7636) subcommand.
type browserFlags struct {
	clientID     string
	clientSecret string
	scopes       string
	resource     string
	callbackPort int
	noBrowser    bool
	timeout      time.Duration
}

func newBrowserCommand(tf *tokenFlags) *cobra.Command {
	bf := &browserFlags{}
	cmd := &cobra.Command{
		Use:   "browser <issuer>",
		Short: "Acquire a token via the browser (authorization code + PKCE)",
		Long: `Acquire an access token via the OAuth 2.0 authorization code flow
with PKCE (RFC 8252 + RFC 7636). The CLI starts a temporary loopback
HTTP server, opens the user's browser to the AS authorization endpoint,
waits for the redirect, and exchanges the code at the token endpoint.

With --no-browser, the auth URL is printed to stderr instead of opened —
useful for SSH sessions where the browser lives on a different host.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBrowser(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], tf, bf)
		},
	}
	cmd.Flags().StringVar(&bf.clientID, "client-id", "", "OAuth client ID (required)")
	cmd.Flags().StringVar(&bf.clientSecret, "client-secret", "", "OAuth client secret (omit for public clients)")
	cmd.Flags().StringVar(&bf.scopes, "scopes", "", `space-delimited OAuth scopes (e.g., "openid profile")`)
	cmd.Flags().StringVar(&bf.resource, "resource", "", "RFC 8707 resource indicator (target audience URI)")
	cmd.Flags().IntVar(&bf.callbackPort, "callback-port", 0, "loopback callback port (0 = pick a free port)")
	cmd.Flags().BoolVar(&bf.noBrowser, "no-browser", false, "print the auth URL to stderr instead of opening a browser")
	cmd.Flags().DurationVar(&bf.timeout, "timeout", 5*time.Minute, "how long to wait for the browser callback")
	_ = cmd.MarkFlagRequired("client-id")
	return cmd
}

// runBrowser is the body of `oneauth token browser`. Split out so tests
// can call it directly with substitute writers without going through
// cobra's Execute machinery.
func runBrowser(ctx context.Context, stdout, stderr io.Writer, issuer string, tf *tokenFlags, bf *browserFlags) error {
	ac, meta, err := newAuthClient(issuer)
	if err != nil {
		return err
	}

	req := &client.BrowserLoginRequest{
		ClientID:     bf.clientID,
		ClientSecret: bf.clientSecret,
		Scopes:       splitScopes(bf.scopes),
		Resource:     bf.resource,
		CallbackPort: bf.callbackPort,
		Timeout:      bf.timeout,
	}
	if bf.noBrowser {
		req.OpenBrowser = printAuthURL(stderr)
	}

	cred, err := ac.LoginWithBrowser(ctx, req)
	if err != nil {
		return fmt.Errorf("browser login: %w", err)
	}
	return emit(stdout, tf.format, cred, issuerFromMeta(meta, issuer), time.Now())
}

// printAuthURL is the OpenBrowser hook used when --no-browser is set.
// It prints the URL on its own line to stderr (so stdout stays a clean
// machine-parseable channel) and returns nil — the loopback server is
// still listening for the redirect on this host.
func printAuthURL(stderr io.Writer) func(string) error {
	return func(authURL string) error {
		fmt.Fprintln(stderr, "Open this URL in a browser:")
		fmt.Fprintln(stderr, "  "+authURL)
		fmt.Fprintln(stderr, "Waiting for callback...")
		return nil
	}
}

// issuerFromMeta returns the issuer URL the CLI should advertise in its
// output. Prefers the discovery-confirmed issuer (RFC 8414's `issuer`
// claim) over the user-supplied URL, since they may differ in trailing
// slashes or path components.
func issuerFromMeta(meta *client.ASMetadata, fallback string) string {
	if meta != nil && meta.Issuer != "" {
		return meta.Issuer
	}
	return fallback
}
