package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/panyam/oneauth/client"
)

// tokenOutput is the wire shape printed by `--format json`. Field names
// match the OAuth 2.0 token response so consumers parsing CLI stdout can
// reuse RFC 6749 §5.1 parsers without translation.
type tokenOutput struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
}

// expiresInFromCredential reverses the SDK's normalization back into the
// RFC 6749 §5.1 `expires_in` (seconds remaining). Returns 0 when the
// credential has no expiry, mirroring the AS omission of the field.
func expiresInFromCredential(cred *client.ServerCredential, now time.Time) int64 {
	if cred.ExpiresAt.IsZero() {
		return 0
	}
	d := cred.ExpiresAt.Sub(now).Seconds()
	if d <= 0 {
		return 0
	}
	return int64(math.Floor(d))
}

// emit dispatches the credential to the writer using the format string
// supplied by the user. `--format json` and `bash` go to w (typically
// stdout). `access-token-only` likewise — no trailing newline so
// `$(oneauth token ...)` doesn't smuggle one into shell-interpolated
// contexts.
//
// `now` is taken as a parameter rather than reading time.Now() so tests
// can pin a deterministic `expires_in`.
func emit(w io.Writer, format string, cred *client.ServerCredential, issuer string, now time.Time) error {
	switch format {
	case "", "json":
		out := tokenOutput{
			AccessToken:  cred.AccessToken,
			RefreshToken: cred.RefreshToken,
			ExpiresIn:    expiresInFromCredential(cred, now),
			TokenType:    cred.TokenType,
			Scope:        cred.Scope,
			Issuer:       issuer,
		}
		if out.TokenType == "" {
			out.TokenType = "Bearer"
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(&out)

	case "bash":
		// Sourceable: `eval "$(oneauth token client-credentials ...)"`
		// drops the variables into the calling shell.
		if _, err := fmt.Fprintf(w, "export OAUTH_ACCESS_TOKEN=%s\n", shellSingleQuote(cred.AccessToken)); err != nil {
			return err
		}
		if cred.RefreshToken != "" {
			if _, err := fmt.Fprintf(w, "export OAUTH_REFRESH_TOKEN=%s\n", shellSingleQuote(cred.RefreshToken)); err != nil {
				return err
			}
		}
		if !cred.ExpiresAt.IsZero() {
			if _, err := fmt.Fprintf(w, "export OAUTH_EXPIRES_AT=%d\n", cred.ExpiresAt.Unix()); err != nil {
				return err
			}
		}
		if issuer != "" {
			if _, err := fmt.Fprintf(w, "export OAUTH_ISSUER=%s\n", shellSingleQuote(issuer)); err != nil {
				return err
			}
		}
		return nil

	case "access-token-only":
		_, err := fmt.Fprint(w, cred.AccessToken)
		return err

	default:
		return fmt.Errorf("unknown format %q (want json | bash | access-token-only)", format)
	}
}

// shellSingleQuote single-quotes a string for safe embedding in a bash
// `export X=...` statement. The only character that can't appear inside
// a single-quoted literal is `'` itself — replace `'` with `'\''` (close
// quote, escaped quote, reopen quote) per the standard shell idiom.
func shellSingleQuote(s string) string {
	const escape = `'\''`
	out := make([]byte, 0, len(s)+2)
	out = append(out, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, escape...)
			continue
		}
		out = append(out, s[i])
	}
	out = append(out, '\'')
	return string(out)
}

// readAllStdin is a tiny indirection so token.go can read stdin without
// importing io directly — keeps the subcommand files free of incidental
// imports and lets tests substitute fixtures.
func readAllStdin(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
