package fs_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/panyam/oneauth/outbound"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/panyam/oneauth/usertokentest"
)

func TestFSUserTokenStore_Contract(t *testing.T) {
	usertokentest.RunAll(t, func(t *testing.T) outbound.UserTokenStore {
		return fs.NewFSUserTokenStore(t.TempDir())
	})
}

// The file name comes from a hash, so a subject can't steer the path out
// of the store's directory.
// See: https://cwe.mitre.org/data/definitions/22.html
func TestFSUserTokenStore_SubjectCantEscapeDirectory(t *testing.T) {
	root := t.TempDir()
	s := fs.NewFSUserTokenStore(filepath.Join(root, "store"))
	if _, err := s.PutUserToken(context.Background(), &outbound.PutUserTokenRequest{Provider: "github", Subject: "../../escape", Sealed: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasPrefix(p, filepath.Join(root, "store", "user_tokens")) {
			t.Errorf("file written outside the store: %s", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
