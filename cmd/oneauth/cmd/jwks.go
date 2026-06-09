package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/panyam/oneauth/utils"
	"github.com/spf13/cobra"
)

// jwksFlags carries the options for `oneauth jwks`.
type jwksFlags struct {
	format string
	sigOnly bool
	kid     string
}

// newJWKSCommand builds `oneauth jwks <issuer>` — fetch the AS's JWKS
// and pretty-print it. Routine debugging tool: confirm kid matches a
// token header, check the advertised alg, compare across rotations.
//
// jwks_uri is resolved via OIDC / RFC 8414 discovery; if the issuer's
// metadata omits it the command fails loudly rather than guessing
// /.well-known/jwks.json.
func newJWKSCommand() *cobra.Command {
	jf := &jwksFlags{}
	cmd := &cobra.Command{
		Use:   "jwks <issuer>",
		Short: "Fetch and pretty-print the auth server's JWKS",
		Long: `Fetch the auth server's JWKS (RFC 7517) from its advertised
` + "`jwks_uri`" + ` and print it. Pair with --kid to surface just the
key matching a token header, or --sig-only to drop verification-only
keys filtered by use=sig.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runJWKS(cmd.Context(), cmd.OutOrStdout(), args[0], jf)
		},
	}
	cmd.Flags().StringVar(&jf.format, "format", "json", `output format: "json" | "table"`)
	cmd.Flags().BoolVar(&jf.sigOnly, "sig-only", false, `print only keys with use="sig"`)
	cmd.Flags().StringVar(&jf.kid, "kid", "", "print only the key matching this kid")
	return cmd
}

func runJWKS(ctx context.Context, stdout io.Writer, issuer string, jf *jwksFlags) error {
	_, meta, err := newAuthClient(issuer)
	if err != nil {
		return err
	}
	if meta.JWKSURI == "" {
		return fmt.Errorf("jwks_uri not advertised by %s", issuer)
	}
	set, err := fetchJWKS(ctx, meta.JWKSURI)
	if err != nil {
		return err
	}
	set = filterJWKS(set, jf)
	return emitJWKS(stdout, jf.format, set)
}

// fetchJWKS GETs the JWKS URL and unmarshals it. Surfaces non-2xx
// statuses as errors rather than parsing whatever HTML the AS returned.
func fetchJWKS(ctx context.Context, url string) (*utils.JWKSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks (%s): %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jwks %s returned %d", url, resp.StatusCode)
	}
	var set utils.JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	return &set, nil
}

// filterJWKS narrows the set by --kid / --sig-only. Returns the input
// unchanged when no filters apply so the caller observes the original
// JWKS shape.
func filterJWKS(set *utils.JWKSet, jf *jwksFlags) *utils.JWKSet {
	if jf.kid == "" && !jf.sigOnly {
		return set
	}
	out := &utils.JWKSet{}
	for _, k := range set.Keys {
		if jf.kid != "" && k.Kid != jf.kid {
			continue
		}
		if jf.sigOnly && k.Use != "" && k.Use != "sig" {
			continue
		}
		out.Keys = append(out.Keys, k)
	}
	return out
}

// emitJWKS prints the (possibly filtered) JWKS. The "table" format is a
// human-scan-friendly two-column summary; the underlying parameters
// (n, e, x, y) are usually not what you want at the terminal.
func emitJWKS(w io.Writer, format string, set *utils.JWKSet) error {
	switch format {
	case "", "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(set)
	case "table":
		fmt.Fprintf(w, "%-10s %-8s %-6s %-6s %s\n", "ALG", "USE", "KTY", "CRV", "KID")
		for _, k := range set.Keys {
			fmt.Fprintf(w, "%-10s %-8s %-6s %-6s %s\n", k.Alg, k.Use, k.Kty, k.Crv, k.Kid)
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json | table)", format)
	}
}
