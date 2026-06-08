package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/spf13/cobra"
)

type clientCredsFlags struct {
	clientID          string
	clientSecret      string
	clientSecretStdin bool
	scopes            string
	resource          string
}

func newClientCredentialsCommand(tf *tokenFlags) *cobra.Command {
	cc := &clientCredsFlags{}
	cmd := &cobra.Command{
		Use:     "client-credentials <issuer>",
		Aliases: []string{"cc"},
		Short:   "Acquire a machine-to-machine token (RFC 6749 §4.4 client_credentials)",
		Long: `Acquire an access token via the OAuth 2.0 client_credentials grant
(RFC 6749 §4.4). Suited for service-to-service / CI use where no human
is in the loop.

Use --client-secret-stdin to avoid leaking the secret into shell history
or process listings.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientCredentials(cmd.Context(), cmd.OutOrStdout(), args[0], tf, cc)
		},
	}
	cmd.Flags().StringVar(&cc.clientID, "client-id", "", "OAuth client ID (required)")
	cmd.Flags().StringVar(&cc.clientSecret, "client-secret", "", "OAuth client secret (required unless --client-secret-stdin)")
	cmd.Flags().BoolVar(&cc.clientSecretStdin, "client-secret-stdin", false, "read client secret from stdin")
	cmd.Flags().StringVar(&cc.scopes, "scopes", "", `space-delimited OAuth scopes (e.g., "read write")`)
	cmd.Flags().StringVar(&cc.resource, "resource", "", "RFC 8707 resource indicator (target audience URI)")
	_ = cmd.MarkFlagRequired("client-id")
	return cmd
}

func runClientCredentials(ctx context.Context, stdout io.Writer, issuer string, tf *tokenFlags, cc *clientCredsFlags) error {
	secret, err := resolveSecret(cc.clientSecret, cc.clientSecretStdin, "--client-secret")
	if err != nil {
		return err
	}

	ac, meta, err := newAuthClient(issuer)
	if err != nil {
		return err
	}

	req := &client.ClientCredentialsRequest{
		ClientID:     cc.clientID,
		ClientSecret: secret,
		Scopes:       splitScopes(cc.scopes),
	}
	if cc.resource != "" {
		req.Resources = []string{cc.resource}
	}
	cred, err := ac.ClientCredentials(ctx, req)
	if err != nil {
		return fmt.Errorf("client_credentials: %w", err)
	}
	return emit(stdout, tf.format, cred, issuerFromMeta(meta, issuer), time.Now())
}

// resolveSecret picks the secret value from --flag or --flag-stdin and
// rejects the combinations that don't make sense: both set, or both
// unset for a required secret.
func resolveSecret(literal string, fromStdin bool, flagName string) (string, error) {
	switch {
	case literal != "" && fromStdin:
		return "", fmt.Errorf("%s and %s-stdin are mutually exclusive", flagName, flagName)
	case fromStdin:
		s, err := readStdinSecret()
		if err != nil {
			return "", fmt.Errorf("read %s from stdin: %w", flagName, err)
		}
		if s == "" {
			return "", fmt.Errorf("%s-stdin produced an empty value", flagName)
		}
		return s, nil
	default:
		return literal, nil
	}
}
