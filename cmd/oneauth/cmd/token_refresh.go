package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/spf13/cobra"
)

type refreshFlags struct {
	clientID          string
	clientSecret      string
	clientSecretStdin bool
	refreshToken      string
	refreshTokenStdin bool
	scopes            string
}

func newRefreshCommand(tf *tokenFlags) *cobra.Command {
	rf := &refreshFlags{}
	cmd := &cobra.Command{
		Use:   "refresh <issuer>",
		Short: "Exchange a refresh token for a fresh access token (RFC 6749 §6)",
		Long: `Exchange a long-lived refresh token for a new access token via the
OAuth 2.0 refresh_token grant (RFC 6749 §6). Confidential clients pass
--client-secret; public PKCE-origin clients omit it.

Use --refresh-token-stdin / --client-secret-stdin to avoid leaking
secrets into shell history or process listings.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRefresh(cmd.Context(), cmd.OutOrStdout(), args[0], tf, rf)
		},
	}
	cmd.Flags().StringVar(&rf.clientID, "client-id", "", "OAuth client ID (required)")
	cmd.Flags().StringVar(&rf.clientSecret, "client-secret", "", "OAuth client secret (confidential clients only)")
	cmd.Flags().BoolVar(&rf.clientSecretStdin, "client-secret-stdin", false, "read client secret from stdin")
	cmd.Flags().StringVar(&rf.refreshToken, "refresh-token", "", "refresh token to exchange (required unless --refresh-token-stdin)")
	cmd.Flags().BoolVar(&rf.refreshTokenStdin, "refresh-token-stdin", false, "read refresh token from stdin")
	cmd.Flags().StringVar(&rf.scopes, "scopes", "", `space-delimited subset of the original scopes to request`)
	_ = cmd.MarkFlagRequired("client-id")
	return cmd
}

func runRefresh(ctx context.Context, stdout io.Writer, issuer string, tf *tokenFlags, rf *refreshFlags) error {
	rt, err := resolveSecret(rf.refreshToken, rf.refreshTokenStdin, "--refresh-token")
	if err != nil {
		return err
	}
	if rt == "" {
		return fmt.Errorf("--refresh-token (or --refresh-token-stdin) is required")
	}
	secret, err := resolveSecret(rf.clientSecret, rf.clientSecretStdin, "--client-secret")
	if err != nil {
		return err
	}

	ac, meta, err := newAuthClient(issuer)
	if err != nil {
		return err
	}

	cred, err := ac.RefreshToken(ctx, &client.RefreshTokenRequest{
		ClientID:     rf.clientID,
		ClientSecret: secret,
		RefreshToken: rt,
		Scopes:       splitScopes(rf.scopes),
	})
	if err != nil {
		return fmt.Errorf("refresh: %w", err)
	}
	return emit(stdout, tf.format, cred, issuerFromMeta(meta, issuer), time.Now())
}
