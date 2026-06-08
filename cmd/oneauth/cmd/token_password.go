package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/spf13/cobra"
)

type passwordFlags struct {
	clientID      string
	clientSecret  string
	user          string
	password      string
	passwordStdin bool
	scopes        string
}

func newPasswordCommand(tf *tokenFlags) *cobra.Command {
	pf := &passwordFlags{}
	cmd := &cobra.Command{
		Use:   "password <issuer>",
		Short: "Acquire a token via the resource-owner password grant (deprecated)",
		Long: `Acquire an access token via the OAuth 2.0 resource-owner password
credentials grant (RFC 6749 §4.3). DEPRECATED by OAuth 2.1 — included
only for CI pipelines against ASes that still allow it. A warning is
printed to stderr on every invocation.

Use --password-stdin to avoid leaking the password into shell history or
process listings.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPassword(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], tf, pf)
		},
	}
	cmd.Flags().StringVar(&pf.clientID, "client-id", "", "OAuth client ID (required)")
	cmd.Flags().StringVar(&pf.clientSecret, "client-secret", "", "OAuth client secret for confidential clients (omit for public clients)")
	cmd.Flags().StringVar(&pf.user, "user", "", "resource owner username (required)")
	cmd.Flags().StringVar(&pf.password, "password", "", "resource owner password (required unless --password-stdin)")
	cmd.Flags().BoolVar(&pf.passwordStdin, "password-stdin", false, "read password from stdin")
	cmd.Flags().StringVar(&pf.scopes, "scopes", "", `space-delimited OAuth scopes (e.g., "openid")`)
	_ = cmd.MarkFlagRequired("client-id")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func runPassword(ctx context.Context, stdout, stderr io.Writer, issuer string, tf *tokenFlags, pf *passwordFlags) error {
	fmt.Fprintln(stderr, "warning: the password grant (ROPC) is deprecated by OAuth 2.1 — prefer the browser flow")

	pw, err := resolveSecret(pf.password, pf.passwordStdin, "--password")
	if err != nil {
		return err
	}
	if pw == "" {
		return fmt.Errorf("--password (or --password-stdin) is required")
	}

	ac, meta, err := newAuthClient(issuer)
	if err != nil {
		return err
	}

	cred, err := ac.Login(ctx, &client.LoginRequest{
		Username:     pf.user,
		Password:     pw,
		Scope:        joinScopes(pf.scopes),
		ClientID:     pf.clientID,
		ClientSecret: pf.clientSecret,
	})
	if err != nil {
		return fmt.Errorf("password grant: %w", err)
	}
	return emit(stdout, tf.format, cred, issuerFromMeta(meta, issuer), time.Now())
}

// joinScopes returns the trimmed scopes string for the AuthClient.Login
// API, which still takes Scope as a space-delimited string rather than
// a []string. Empty input yields "" so the SDK omits the form value.
func joinScopes(s string) string {
	return strings.Join(splitScopes(s), " ")
}

