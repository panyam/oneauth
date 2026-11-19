//go:build windows

package outbound_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/panyam/oneauth/outbound"
)

// See: https://github.com/panyam/oneauth/issues/499
func TestSecretRef_WindowsDrivePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.pem")
	if filepath.VolumeName(path) == "" {
		t.Fatalf("temp path %q has no drive letter", path)
	}
	if err := os.WriteFile(path, []byte("key\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ref, err := outbound.ParseSecretRef("file:" + path)
	if err != nil {
		t.Fatalf("file:%s refused: %v", path, err)
	}
	if v, err := ref.Resolve(); err != nil || v != "key" {
		t.Fatalf("Resolve: %q, %v", v, err)
	}
	if ref.String() != "file:"+path {
		t.Fatalf("String() = %q", ref.String())
	}
}

// A path with no volume, or a drive-relative one, depends on the current
// drive or directory, so it is refused like a relative path.
func TestSecretRef_WindowsNotAbsoluteRefused(t *testing.T) {
	for _, in := range []string{`file:\secrets\app.pem`, `file:C:secrets\app.pem`, `file:secrets\app.pem`} {
		if _, err := outbound.ParseSecretRef(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
