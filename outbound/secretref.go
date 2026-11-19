// Package outbound holds credentials an app uses to call third-party APIs
// on its own or for its users, as opposed to signing people in to the app.
// Each source is an oauth2.TokenSource, so oauth2.NewClient turns it into
// an *http.Client and any HTTP-based SDK can use it.
//
//   - GitHubAppInstallation mints a GitHub App's JWT and trades it for an
//     installation token, cached until shortly before it expires.
//   - StoredUserToken is a person's token from a connect flow, kept sealed
//     in a UserTokenStore and refreshed (and written back) when it expires.
//   - Static is a fixed secret such as a personal access token, read from
//     a SecretRef so it never appears in config.
//
// See docs/OUTBOUND_CREDENTIALS.md for the design and the threat notes.
package outbound

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SecretRef names where a secret lives, never the secret itself. Two forms
// are accepted:
//
//	env:NAME      the environment variable NAME
//	file:PATH     the contents of the file at PATH (a mounted secret)
//
// PATH is absolute: /run/secrets/app.pem, or C:\secrets\app.pem on Windows.
//
// Anything else is refused by ParseSecretRef, including a bare value, so a
// token pasted into config fails at startup instead of being stored there.
type SecretRef struct {
	kind string // "env" or "file"
	name string
}

// ErrSecretMissing is returned by Resolve when the variable is unset, the
// file can't be read, or either holds only whitespace. The error names the
// reference and never the value.
var ErrSecretMissing = errors.New("outbound: secret not found")

// ParseSecretRef parses "env:NAME" or "file:PATH". PATH must start with
// "/" or be absolute by filepath.IsAbs, so a reference means the same thing
// whatever the working directory is. On Windows that admits C:\path and
// \\server\share\path, and refuses C:path, which depends on the current
// directory of drive C. A path starting with "/" is accepted on every OS.
func ParseSecretRef(s string) (SecretRef, error) {
	kind, name, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || name == "" {
		return SecretRef{}, fmt.Errorf("outbound: secret reference must be env:NAME or file:PATH")
	}
	switch kind {
	case "env":
		if strings.ContainsAny(name, "= \t\n") {
			return SecretRef{}, fmt.Errorf("outbound: env secret reference has an invalid variable name")
		}
	case "file":
		if !strings.HasPrefix(name, "/") && !filepath.IsAbs(name) {
			return SecretRef{}, fmt.Errorf("outbound: file secret reference %q must be an absolute path", "file:"+name)
		}
	default:
		// The input may be the secret itself, so it is left out of the error.
		return SecretRef{}, fmt.Errorf("outbound: secret reference must be env:NAME or file:PATH")
	}
	return SecretRef{kind: kind, name: name}, nil
}

// MustParseSecretRef is ParseSecretRef for literals in code and tests. It
// panics on an invalid reference.
func MustParseSecretRef(s string) SecretRef {
	ref, err := ParseSecretRef(s)
	if err != nil {
		panic(err)
	}
	return ref
}

// String returns the reference in the form ParseSecretRef accepts. It is
// safe to log.
func (r SecretRef) String() string {
	if r.kind == "" {
		return ""
	}
	return r.kind + ":" + r.name
}

// IsZero reports whether r is the zero SecretRef.
func (r SecretRef) IsZero() bool { return r.kind == "" }

// Resolve reads the secret each time it is called, so a rotated file or
// variable takes effect without a restart. Surrounding whitespace is
// trimmed, as mounted secrets often end in a newline.
func (r SecretRef) Resolve() (string, error) {
	var v string
	switch r.kind {
	case "env":
		v = os.Getenv(r.name)
	case "file":
		b, err := os.ReadFile(r.name)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrSecretMissing, r)
		}
		v = string(b)
	default:
		return "", fmt.Errorf("%w: empty reference", ErrSecretMissing)
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("%w: %s", ErrSecretMissing, r)
	}
	return v, nil
}
