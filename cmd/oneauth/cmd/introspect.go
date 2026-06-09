package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/panyam/oneauth/apiauth"
	"github.com/spf13/cobra"
)

// introspectFlags carries the inputs for `oneauth introspect`.
type introspectFlags struct {
	token             string
	tokenStdin        bool
	clientID          string
	clientSecret      string
	clientSecretStdin bool
	format            string
}

// newIntrospectCommand builds `oneauth introspect <issuer>`. The verb is
// a sibling of `token` rather than a child because it answers a
// completely different question — "is this token still active?" — and
// the RFC 7662 wire format has no overlap with token issuance.
//
// The CLI dogfoods apiauth.IntrospectionValidator so any future
// behavior change (tracing, header handling) lands here automatically.
func newIntrospectCommand() *cobra.Command {
	ff := &introspectFlags{}
	cmd := &cobra.Command{
		Use:   "introspect <issuer>",
		Short: "Check a token's validity via RFC 7662 introspection",
		Long: `Call the auth server's introspection endpoint (RFC 7662) to check
whether a token is active and read its claims (sub, scope, exp, iss, jti, aud).

The issuer is the AS base URL — the introspection endpoint is resolved
via OIDC / RFC 8414 discovery (` + "`/.well-known/openid-configuration`" + `).

Use --token-stdin and --client-secret-stdin to keep secrets out of
shell history and process listings.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIntrospect(cmd.Context(), cmd.OutOrStdout(), args[0], ff)
		},
	}
	cmd.Flags().StringVar(&ff.token, "token", "", "token to introspect (required unless --token-stdin)")
	cmd.Flags().BoolVar(&ff.tokenStdin, "token-stdin", false, "read token from stdin")
	cmd.Flags().StringVar(&ff.clientID, "client-id", "", "client_id authenticating to the introspection endpoint (required)")
	cmd.Flags().StringVar(&ff.clientSecret, "client-secret", "", "client_secret (required unless --client-secret-stdin)")
	cmd.Flags().BoolVar(&ff.clientSecretStdin, "client-secret-stdin", false, "read client secret from stdin")
	cmd.Flags().StringVar(&ff.format, "format", "json", `output format: "json" | "active"`)
	_ = cmd.MarkFlagRequired("client-id")
	return cmd
}

func runIntrospect(ctx context.Context, stdout io.Writer, issuer string, ff *introspectFlags) error {
	token, err := resolveSecret(ff.token, ff.tokenStdin, "--token")
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("--token (or --token-stdin) is required")
	}
	secret, err := resolveSecret(ff.clientSecret, ff.clientSecretStdin, "--client-secret")
	if err != nil {
		return err
	}

	_, meta, err := newAuthClient(issuer)
	if err != nil {
		return err
	}
	if meta.IntrospectionEndpoint == "" {
		return fmt.Errorf("introspection_endpoint not advertised by %s", issuer)
	}

	iv := &apiauth.IntrospectionValidator{
		IntrospectionURL: meta.IntrospectionEndpoint,
		ClientID:         ff.clientID,
		ClientSecret:     secret,
		HTTPClient:       http.DefaultClient,
	}
	result, err := iv.ValidateWithContext(ctx, token)
	if err != nil {
		return fmt.Errorf("introspect: %w", err)
	}
	return emitIntrospection(stdout, ff.format, result)
}

// emitIntrospection writes the introspection result in the requested
// format. The "active" format prints just `true` / `false` — useful as
// the predicate of a shell `if`.
func emitIntrospection(w io.Writer, format string, r *apiauth.IntrospectionResult) error {
	switch format {
	case "", "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "active":
		_, err := fmt.Fprintln(w, r.Active)
		return err
	default:
		return fmt.Errorf("unknown format %q (want json | active)", format)
	}
}
