package outbound_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/panyam/oneauth/outbound"
)

func TestSecretRef_EnvAndFileResolve(t *testing.T) {
	t.Setenv("OUTBOUND_TEST_PAT", "ghp_fromenv\n")
	ref := outbound.MustParseSecretRef("env:OUTBOUND_TEST_PAT")
	if v, err := ref.Resolve(); err != nil || v != "ghp_fromenv" {
		t.Fatalf("env: %q, %v", v, err)
	}

	path := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(path, []byte("ghp_fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ref = outbound.MustParseSecretRef("file:" + path)
	if v, err := ref.Resolve(); err != nil || v != "ghp_fromfile" {
		t.Fatalf("file: %q, %v", v, err)
	}
	// A rotated file is read on the next call.
	if err := os.WriteFile(path, []byte("ghp_rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, _ := ref.Resolve(); v != "ghp_rotated" {
		t.Fatalf("after rotation: %q", v)
	}
}

// A token pasted where a reference belongs is refused, and the error
// doesn't repeat it.
// See: https://cwe.mitre.org/data/definitions/798.html
func TestSecretRef_LiteralRefused(t *testing.T) {
	for _, in := range []string{"ghp_abcdef123456", "gh:ghp_abcdef123456", "env:", "file:relative/path", "env:A=B"} {
		_, err := outbound.ParseSecretRef(in)
		if err == nil {
			t.Errorf("%q accepted", in)
			continue
		}
		if strings.Contains(err.Error(), "abcdef123456") {
			t.Errorf("%q: error repeats the input: %v", in, err)
		}
	}
}

// See: https://cwe.mitre.org/data/definitions/532.html
func TestSecretRef_MissingNamesReferenceNotValue(t *testing.T) {
	ref := outbound.MustParseSecretRef("env:OUTBOUND_TEST_UNSET")
	_, err := ref.Resolve()
	if !errors.Is(err, outbound.ErrSecretMissing) || !strings.Contains(err.Error(), "env:OUTBOUND_TEST_UNSET") {
		t.Fatalf("got %v", err)
	}
	t.Setenv("OUTBOUND_TEST_BLANK", "   ")
	if _, err := outbound.MustParseSecretRef("env:OUTBOUND_TEST_BLANK").Resolve(); !errors.Is(err, outbound.ErrSecretMissing) {
		t.Fatalf("blank: %v", err)
	}
}

func TestStatic(t *testing.T) {
	if _, err := outbound.NewStatic("env:OUTBOUND_TEST_UNSET"); !errors.Is(err, outbound.ErrSecretMissing) {
		t.Fatalf("NewStatic with a missing secret: %v", err)
	}
	t.Setenv("OUTBOUND_TEST_PAT", "ghp_x")
	s, err := outbound.NewStatic("env:OUTBOUND_TEST_PAT")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Token()
	if err != nil || tok.AccessToken != "ghp_x" || tok.TokenType != "Bearer" || !tok.Expiry.IsZero() {
		t.Fatalf("got %+v, %v", tok, err)
	}
	if s.Ref.String() != "env:OUTBOUND_TEST_PAT" {
		t.Fatalf("String() = %q", s.Ref.String())
	}
}
