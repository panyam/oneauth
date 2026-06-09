package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/panyam/oneauth/client"
	"github.com/spf13/cobra"
)

// dcrFlags holds the persistent --format flag for `oneauth dcr`. Each
// subcommand defines its own request flags directly.
type dcrFlags struct {
	format string
}

// newDCRCommand builds `oneauth dcr`, the RFC 7591 Dynamic Client
// Registration parent. Subcommands are register / get / put / delete —
// the verb set RFC 7592 lays out for the full lifecycle.
func newDCRCommand() *cobra.Command {
	df := &dcrFlags{}
	cmd := &cobra.Command{
		Use:   "dcr",
		Short: "Manage OAuth client registrations (RFC 7591 / RFC 7592)",
		Long: `Register, read, update, and delete OAuth clients via the auth server's
Dynamic Client Registration endpoint (RFC 7591) and management endpoint
(RFC 7592). The registration_access_token returned at registration time
is required for every subsequent management call.`,
	}
	cmd.PersistentFlags().StringVar(&df.format, "format", "json", `output format: "json" | "bash"`)
	cmd.AddCommand(
		newDCRRegisterCommand(df),
		newDCRGetCommand(df),
		newDCRPutCommand(df),
		newDCRDeleteCommand(df),
	)
	return cmd
}

// --- register --------------------------------------------------------

type dcrRegisterFlags struct {
	clientName              string
	clientURI               string
	grantTypes              []string
	responseTypes           []string
	redirectURIs            []string
	scope                   string
	tokenEndpointAuthMethod string
	applicationType         string
}

func newDCRRegisterCommand(df *dcrFlags) *cobra.Command {
	rf := &dcrRegisterFlags{}
	cmd := &cobra.Command{
		Use:   "register <issuer>",
		Short: "Register a new OAuth client (RFC 7591)",
		Long: `POST to the auth server's registration_endpoint (RFC 7591). The AS
assigns a fresh client_id, optional client_secret, and the RFC 7592
management credentials (registration_access_token, registration_client_uri).

Persist the registration_access_token and registration_client_uri — they
are the only way to subsequently read / update / delete this
registration.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDCRRegister(cmd.Context(), cmd.OutOrStdout(), args[0], df, rf)
		},
	}
	cmd.Flags().StringVar(&rf.clientName, "client-name", "", "human-readable client name")
	cmd.Flags().StringVar(&rf.clientURI, "client-uri", "", "client home page URL")
	cmd.Flags().StringSliceVar(&rf.grantTypes, "grant-types", nil, `OAuth grant types (e.g., "authorization_code","refresh_token")`)
	cmd.Flags().StringSliceVar(&rf.responseTypes, "response-types", nil, `OAuth response types (e.g., "code")`)
	cmd.Flags().StringSliceVar(&rf.redirectURIs, "redirect-uri", nil, "redirect URI (repeatable)")
	cmd.Flags().StringVar(&rf.scope, "scope", "", `space-delimited OAuth scopes (e.g., "read write")`)
	cmd.Flags().StringVar(&rf.tokenEndpointAuthMethod, "token-endpoint-auth-method", "", `auth method: "client_secret_basic" | "client_secret_post" | "private_key_jwt" | "none"`)
	cmd.Flags().StringVar(&rf.applicationType, "application-type", "", `OIDC application type: "web" | "native"`)
	return cmd
}

func runDCRRegister(_ context.Context, stdout io.Writer, issuer string, df *dcrFlags, rf *dcrRegisterFlags) error {
	_, meta, err := newAuthClient(issuer)
	if err != nil {
		return err
	}
	if meta.RegistrationEndpoint == "" {
		return fmt.Errorf("registration_endpoint not advertised by %s", issuer)
	}
	req := client.ClientRegistrationRequest{
		ClientName:              rf.clientName,
		ClientURI:               rf.clientURI,
		RedirectURIs:            rf.redirectURIs,
		GrantTypes:              rf.grantTypes,
		ResponseTypes:           rf.responseTypes,
		TokenEndpointAuthMethod: rf.tokenEndpointAuthMethod,
		Scope:                   rf.scope,
		ApplicationType:         rf.applicationType,
	}
	resp, err := client.RegisterClient(meta.RegistrationEndpoint, req, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("dcr register: %w", err)
	}
	return emitDCR(stdout, df.format, resp)
}

// --- get -------------------------------------------------------------

type dcrGetFlags struct {
	clientID                string
	registrationAccessToken string
	registrationClientURI   string
}

func newDCRGetCommand(df *dcrFlags) *cobra.Command {
	gf := &dcrGetFlags{}
	cmd := &cobra.Command{
		Use:   "get <issuer>",
		Short: "Read a registered client (RFC 7592 §2.1)",
		Long: `GET the management endpoint for an existing registration. Either
--registration-client-uri (the absolute URI returned at registration
time) or --client-id (resolved against the issuer's registration_endpoint
+ client_id path) is required.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDCRGet(cmd.Context(), cmd.OutOrStdout(), args[0], df, gf)
		},
	}
	dcrManagementFlags(cmd, &gf.clientID, &gf.registrationAccessToken, &gf.registrationClientURI)
	_ = cmd.MarkFlagRequired("registration-access-token")
	return cmd
}

func runDCRGet(ctx context.Context, stdout io.Writer, issuer string, df *dcrFlags, gf *dcrGetFlags) error {
	uri, err := resolveManagementURI(issuer, gf.clientID, gf.registrationClientURI)
	if err != nil {
		return err
	}
	resp, err := client.GetRegistration(ctx, &client.GetRegistrationRequest{
		RegistrationClientURI:   uri,
		RegistrationAccessToken: gf.registrationAccessToken,
	})
	if err != nil {
		return mapRegistrationErr(err, "dcr get")
	}
	return emitDCR(stdout, df.format, resp.Registration)
}

// --- put (update) ----------------------------------------------------

type dcrPutFlags struct {
	clientID                string
	registrationAccessToken string
	registrationClientURI   string
	clientName              string
	clientURI               string
	grantTypes              []string
	responseTypes           []string
	redirectURIs            []string
	scope                   string
	tokenEndpointAuthMethod string
	applicationType         string
}

func newDCRPutCommand(df *dcrFlags) *cobra.Command {
	pf := &dcrPutFlags{}
	cmd := &cobra.Command{
		Use:   "put <issuer>",
		Short: "Replace a registered client's metadata (RFC 7592 §2.2)",
		Long: `PUT to the management endpoint. RFC 7592 treats this as a
full-replace — fields you omit are blanked. Fetch first with
` + "`oneauth dcr get`" + ` and edit the response if you only want to
change a subset of fields. The AS rotates the registration_access_token
on success; the new token is in the response.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDCRPut(cmd.Context(), cmd.OutOrStdout(), args[0], df, pf)
		},
	}
	dcrManagementFlags(cmd, &pf.clientID, &pf.registrationAccessToken, &pf.registrationClientURI)
	cmd.Flags().StringVar(&pf.clientName, "client-name", "", "human-readable client name")
	cmd.Flags().StringVar(&pf.clientURI, "client-uri", "", "client home page URL")
	cmd.Flags().StringSliceVar(&pf.grantTypes, "grant-types", nil, "OAuth grant types")
	cmd.Flags().StringSliceVar(&pf.responseTypes, "response-types", nil, "OAuth response types")
	cmd.Flags().StringSliceVar(&pf.redirectURIs, "redirect-uri", nil, "redirect URI (repeatable)")
	cmd.Flags().StringVar(&pf.scope, "scope", "", `space-delimited OAuth scopes`)
	cmd.Flags().StringVar(&pf.tokenEndpointAuthMethod, "token-endpoint-auth-method", "", "auth method")
	cmd.Flags().StringVar(&pf.applicationType, "application-type", "", `OIDC application type: "web" | "native"`)
	_ = cmd.MarkFlagRequired("client-id")
	_ = cmd.MarkFlagRequired("registration-access-token")
	return cmd
}

func runDCRPut(ctx context.Context, stdout io.Writer, issuer string, df *dcrFlags, pf *dcrPutFlags) error {
	uri, err := resolveManagementURI(issuer, pf.clientID, pf.registrationClientURI)
	if err != nil {
		return err
	}
	resp, err := client.UpdateRegistration(ctx, &client.UpdateRegistrationRequest{
		RegistrationClientURI:   uri,
		RegistrationAccessToken: pf.registrationAccessToken,
		ClientID:                pf.clientID,
		Metadata: client.ClientRegistrationRequest{
			ClientName:              pf.clientName,
			ClientURI:               pf.clientURI,
			RedirectURIs:            pf.redirectURIs,
			GrantTypes:              pf.grantTypes,
			ResponseTypes:           pf.responseTypes,
			Scope:                   pf.scope,
			TokenEndpointAuthMethod: pf.tokenEndpointAuthMethod,
			ApplicationType:         pf.applicationType,
		},
	})
	if err != nil {
		return mapRegistrationErr(err, "dcr put")
	}
	return emitDCR(stdout, df.format, resp.Registration)
}

// --- delete ----------------------------------------------------------

type dcrDeleteFlags struct {
	clientID                string
	registrationAccessToken string
	registrationClientURI   string
}

func newDCRDeleteCommand(df *dcrFlags) *cobra.Command {
	xf := &dcrDeleteFlags{}
	cmd := &cobra.Command{
		Use:   "delete <issuer>",
		Short: "Delete a registered client (RFC 7592 §2.3)",
		Long: `DELETE the management endpoint. The AS invalidates the
registration's signing credentials so any tokens already issued under
this client_id fail subsequent validation.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDCRDelete(cmd.Context(), cmd.OutOrStdout(), args[0], df, xf)
		},
	}
	dcrManagementFlags(cmd, &xf.clientID, &xf.registrationAccessToken, &xf.registrationClientURI)
	_ = cmd.MarkFlagRequired("registration-access-token")
	return cmd
}

func runDCRDelete(ctx context.Context, stdout io.Writer, issuer string, df *dcrFlags, xf *dcrDeleteFlags) error {
	uri, err := resolveManagementURI(issuer, xf.clientID, xf.registrationClientURI)
	if err != nil {
		return err
	}
	if _, err := client.DeleteRegistration(ctx, &client.DeleteRegistrationRequest{
		RegistrationClientURI:   uri,
		RegistrationAccessToken: xf.registrationAccessToken,
	}); err != nil {
		return mapRegistrationErr(err, "dcr delete")
	}
	if df.format == "bash" {
		fmt.Fprintf(stdout, "# deleted %s\n", uri)
		return nil
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"deleted": true, "registration_client_uri": uri})
}

// --- shared helpers --------------------------------------------------

func dcrManagementFlags(cmd *cobra.Command, clientID, accessToken, regURI *string) {
	cmd.Flags().StringVar(clientID, "client-id", "", "client_id (resolved against issuer's registration_endpoint when --registration-client-uri is absent)")
	cmd.Flags().StringVar(accessToken, "registration-access-token", "", "RFC 7592 management token returned at registration (required)")
	cmd.Flags().StringVar(regURI, "registration-client-uri", "", "absolute management URI (overrides --client-id derivation)")
}

// resolveManagementURI computes the registration_client_uri to call. When
// the caller supplies it directly that's the answer; otherwise we
// discover the issuer's registration_endpoint and append /client_id —
// the convention used by oneauth's own admin server. ASes that deviate
// (Keycloak, Auth0) require the caller to pass --registration-client-uri
// explicitly.
func resolveManagementURI(issuer, clientID, registrationClientURI string) (string, error) {
	if registrationClientURI != "" {
		return registrationClientURI, nil
	}
	if clientID == "" {
		return "", fmt.Errorf("--registration-client-uri or --client-id is required")
	}
	_, meta, err := newAuthClient(issuer)
	if err != nil {
		return "", err
	}
	if meta.RegistrationEndpoint == "" {
		return "", fmt.Errorf("registration_endpoint not advertised by %s; pass --registration-client-uri explicitly", issuer)
	}
	return joinPath(meta.RegistrationEndpoint, clientID), nil
}

// joinPath safely appends a path segment. Avoids the double-slash and
// missing-slash failure modes that bite naive string concatenation.
func joinPath(base, segment string) string {
	if base == "" {
		return segment
	}
	if base[len(base)-1] == '/' {
		return base + segment
	}
	return base + "/" + segment
}

// emitDCR writes a registration response in the requested format. The
// "bash" form exports the fields a downstream shell script most often
// needs (client_id, client_secret, registration_access_token).
func emitDCR(w io.Writer, format string, r *client.ClientRegistrationResponse) error {
	switch format {
	case "", "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "bash":
		fmt.Fprintf(w, "export OAUTH_CLIENT_ID=%s\n", shellSingleQuote(r.ClientID))
		if r.ClientSecret != "" {
			fmt.Fprintf(w, "export OAUTH_CLIENT_SECRET=%s\n", shellSingleQuote(r.ClientSecret))
		}
		if r.RegistrationAccessToken != "" {
			fmt.Fprintf(w, "export OAUTH_REGISTRATION_ACCESS_TOKEN=%s\n", shellSingleQuote(r.RegistrationAccessToken))
		}
		if r.RegistrationClientURI != "" {
			fmt.Fprintf(w, "export OAUTH_REGISTRATION_CLIENT_URI=%s\n", shellSingleQuote(r.RegistrationClientURI))
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json | bash)", format)
	}
}

// mapRegistrationErr maps client.ErrRegistrationUnauthorized to a CLI
// message that distinguishes auth failure from generic errors. RFC 7592
// returns 401 for every auth failure mode (wrong token, missing token,
// unknown client_id) so the CLI can't be more specific.
func mapRegistrationErr(err error, prefix string) error {
	if errors.Is(err, client.ErrRegistrationUnauthorized) {
		return fmt.Errorf("%s: unauthorized — check --registration-access-token", prefix)
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
