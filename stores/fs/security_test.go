package fs

// Security test suite for filesystem storage backends.
// Tests path traversal attack vectors, null byte injection, file permissions,
// and documents which stores are already safe vs which needed fixes.
//
// Run with: go test -v -run TestSecurity ./stores/fs/

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maliciousInputs contains path traversal and injection payloads that MUST be rejected.
// Each is a realistic attack vector that could escape the storage directory.
var maliciousInputs = []struct {
	name  string
	input string
}{
	{"parent_traversal", "../../etc/passwd"},
	{"deep_traversal", "../../../tmp/evil"},
	{"backslash_traversal", "..\\..\\etc\\passwd"},
	{"null_byte", "foo\x00bar"},
	{"dot_dot_only", ".."},
	{"dot_dot_slash", "../"},
	{"absolute_path", "/etc/passwd"},
}

// sanitizedInputs are inputs that contain special characters but are safe
// after sanitization — they should succeed, not error.
var sanitizedInputs = []struct {
	name  string
	input string
}{
	{"slash_in_name", "foo/bar/baz"},     // "/" replaced with "_"
	{"hidden_file", ".hidden"},            // valid filename, not ".."
	{"colon_in_name", "email:user@a.com"}, // ":" replaced with "_"
}

// =============================================================================
// Path Traversal: UserStore
// These tests FAIL before the fix — userId goes directly into filepath.Join
// with no sanitization, allowing directory escape.
// =============================================================================

// TestSecurity_PathTraversal_UserStore verifies that path traversal inputs
// in userId are rejected by CreateUser and GetUserById. Before the fix,
// userId="../../etc/passwd" would create a file outside the storage directory.
func TestSecurity_PathTraversal_UserStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFSUserStore(dir)

	for _, tc := range maliciousInputs {
		t.Run("CreateUser_"+tc.name, func(t *testing.T) {
			_, err := store.CreateUser(tc.input, true, map[string]any{"name": "evil"})
			assert.Error(t, err, "CreateUser should reject malicious userId %q", tc.input)

			// Verify no file was created outside the storage directory
			assertNoEscape(t, dir, "users")
		})

		t.Run("GetUserById_"+tc.name, func(t *testing.T) {
			_, err := store.GetUserById(tc.input)
			assert.Error(t, err, "GetUserById should reject malicious userId %q", tc.input)
		})
	}
}

// =============================================================================
// Path Traversal: KeyStore (fskeystore)
// These tests FAIL before the fix — the "/" → "_" replacement is insufficient;
// ".." sequences pass through and filepath.Join normalizes them into escapes.
// =============================================================================

// TestSecurity_PathTraversal_KeyStore verifies that path traversal inputs
// in clientID are rejected by PutKey and GetKey. Before the fix,
// clientID="../../secret" would produce a path like "../../secret.json"
// after only "/" was replaced with "_", leaving ".." intact.
func TestSecurity_PathTraversal_KeyStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFSKeyStore(dir)

	for _, tc := range maliciousInputs {
		t.Run("PutKey_"+tc.name, func(t *testing.T) {
			err := store.PutKey(&keys.KeyRecord{
				ClientID:  tc.input,
				Key:       []byte("test-secret"),
				Algorithm: "HS256",
			})
			assert.Error(t, err, "PutKey should reject malicious clientID %q", tc.input)
			assertNoEscape(t, dir, "keys")
		})

		t.Run("GetKey_"+tc.name, func(t *testing.T) {
			_, err := store.GetKey(tc.input)
			assert.Error(t, err, "GetKey should reject malicious clientID %q", tc.input)
		})
	}
}

// =============================================================================
// Path Traversal: ChannelStore
// These tests FAIL before the fix — the `provider` parameter is completely
// unsanitized and injected directly into the filename via fmt.Sprintf.
// =============================================================================

// TestSecurity_PathTraversal_ChannelStore_Provider verifies that path traversal
// in the provider parameter is rejected. Before the fix, provider="../../etc"
// would escape the channels directory because only identityKey was sanitized.
func TestSecurity_PathTraversal_ChannelStore_Provider(t *testing.T) {
	dir := t.TempDir()
	store := NewFSChannelStore(dir)

	for _, tc := range maliciousInputs {
		t.Run("SaveChannel_provider_"+tc.name, func(t *testing.T) {
			err := store.SaveChannel(&core.Channel{
				Provider:    tc.input,
				IdentityKey: "email:test@example.com",
				Credentials: map[string]any{},
			})
			assert.Error(t, err, "SaveChannel should reject malicious provider %q", tc.input)
			assertNoEscape(t, dir, "channels")
		})

		t.Run("GetChannel_provider_"+tc.name, func(t *testing.T) {
			_, _, err := store.GetChannel(tc.input, "email:test@example.com", false)
			assert.Error(t, err, "GetChannel should reject malicious provider %q", tc.input)
		})
	}
}

// TestSecurity_PathTraversal_ChannelStore_IdentityKey verifies that path
// traversal in identityKey is also caught (even though ":" replacement helps,
// ".." can still escape).
func TestSecurity_PathTraversal_ChannelStore_IdentityKey(t *testing.T) {
	dir := t.TempDir()
	store := NewFSChannelStore(dir)

	for _, tc := range maliciousInputs {
		t.Run("SaveChannel_identityKey_"+tc.name, func(t *testing.T) {
			err := store.SaveChannel(&core.Channel{
				Provider:    "local",
				IdentityKey: tc.input,
				Credentials: map[string]any{},
			})
			assert.Error(t, err, "SaveChannel should reject malicious identityKey %q", tc.input)
		})
	}
}

// =============================================================================
// Path Traversal: TokenStore
// These tests FAIL before the fix — token value goes directly into
// filepath.Join with zero sanitization.
// =============================================================================

// TestSecurity_PathTraversal_TokenStore verifies that path traversal inputs
// in token values are rejected. Before the fix, a crafted token value like
// "../../etc/passwd" would create or read files outside the tokens directory.
func TestSecurity_PathTraversal_TokenStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFSTokenStore(dir)

	for _, tc := range maliciousInputs {
		t.Run("GetToken_"+tc.name, func(t *testing.T) {
			_, err := store.GetToken(tc.input)
			assert.Error(t, err, "GetToken should reject malicious token %q", tc.input)
		})

		t.Run("DeleteToken_"+tc.name, func(t *testing.T) {
			// DeleteToken should not follow traversal paths
			err := store.DeleteToken(tc.input)
			// May return "not found" error which is fine — as long as it doesn't
			// delete files outside the storage directory
			_ = err
			assertNoEscape(t, dir, "tokens")
		})
	}
}

// =============================================================================
// Path Traversal: UsernameStore
// These tests FAIL before the fix — username is only lowercased before
// being used in filepath.Join, allowing full directory traversal.
// =============================================================================

// TestSecurity_PathTraversal_UsernameStore verifies that path traversal
// in usernames is rejected. Before the fix, username="../../etc/passwd"
// would be lowercased to "../../etc/passwd" and used directly in the path.
func TestSecurity_PathTraversal_UsernameStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFSUsernameStore(dir)

	for _, tc := range maliciousInputs {
		t.Run("ReserveUsername_"+tc.name, func(t *testing.T) {
			err := store.ReserveUsername(tc.input, "user123")
			assert.Error(t, err, "ReserveUsername should reject malicious username %q", tc.input)
			assertNoEscape(t, dir, "usernames")
		})

		t.Run("GetUserByUsername_"+tc.name, func(t *testing.T) {
			_, err := store.GetUserByUsername(tc.input)
			assert.Error(t, err, "GetUserByUsername should reject malicious username %q", tc.input)
		})
	}
}

// =============================================================================
// Path Traversal: APIKeyStore
// These tests FAIL before the fix — same issue as KeyStore, "/" → "_"
// replacement is insufficient for ".." sequences.
// =============================================================================

// TestSecurity_PathTraversal_APIKeyStore verifies that path traversal
// in keyID is rejected by GetAPIKeyByID and RevokeAPIKey.
func TestSecurity_PathTraversal_APIKeyStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFSAPIKeyStore(dir)

	for _, tc := range maliciousInputs {
		t.Run("GetAPIKeyByID_"+tc.name, func(t *testing.T) {
			_, err := store.GetAPIKeyByID(tc.input)
			assert.Error(t, err, "GetAPIKeyByID should reject malicious keyID %q", tc.input)
		})

		t.Run("RevokeAPIKey_"+tc.name, func(t *testing.T) {
			err := store.RevokeAPIKey(tc.input)
			// May return "not found" — fine as long as no escape
			_ = err
			assertNoEscape(t, dir, "apikeys")
		})
	}
}

// =============================================================================
// Sanitized inputs: special characters that are safe after sanitization.
// These should SUCCEED (not return errors) — slashes become underscores, etc.
// =============================================================================

// TestSecurity_SanitizedInputs_UserStore verifies that inputs with slashes
// or other non-traversal special characters are accepted after sanitization.
func TestSecurity_SanitizedInputs_UserStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFSUserStore(dir)

	for _, tc := range sanitizedInputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.CreateUser(tc.input, true, map[string]any{"name": "test"})
			assert.NoError(t, err, "CreateUser should accept sanitizable input %q", tc.input)
		})
	}
}

// TestSecurity_SanitizedInputs_KeyStore verifies that key operations accept
// inputs with slashes (sanitized to underscores).
func TestSecurity_SanitizedInputs_KeyStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFSKeyStore(dir)

	for _, tc := range sanitizedInputs {
		t.Run(tc.name, func(t *testing.T) {
			err := store.PutKey(&keys.KeyRecord{
				ClientID:  tc.input,
				Key:       []byte("secret"),
				Algorithm: "HS256",
			})
			assert.NoError(t, err, "PutKey should accept sanitizable input %q", tc.input)
		})
	}
}

// =============================================================================
// Path Traversal: Already-safe stores (document existing protections)
// These tests PASS both before and after the fix.
// =============================================================================

// TestSecurity_PathTraversal_IdentityStore_AlreadySafe documents that the
// identity store uses filepath.Base() which already prevents path traversal.
// These tests pass before and after the fix.
func TestSecurity_PathTraversal_IdentityStore_AlreadySafe(t *testing.T) {
	dir := t.TempDir()
	store := NewFSIdentityStore(dir)

	// filepath.Base strips directory components, so these are safe
	// They return "not found" errors (not traversal), which is correct
	for _, tc := range maliciousInputs {
		t.Run("GetIdentity_"+tc.name, func(t *testing.T) {
			_, _, err := store.GetIdentity("email", tc.input, false)
			// Should either error or return safely within storage dir
			_ = err
			assertNoEscape(t, dir, "identities")
		})
	}
}

// TestSecurity_PathTraversal_RefreshTokenStore_AlreadySafe documents that
// the refresh token store SHA256-hashes tokens before using them in paths,
// making path traversal impossible.
func TestSecurity_PathTraversal_RefreshTokenStore_AlreadySafe(t *testing.T) {
	dir := t.TempDir()
	store := NewFSRefreshTokenStore(dir)

	for _, tc := range maliciousInputs {
		t.Run("GetRefreshToken_"+tc.name, func(t *testing.T) {
			_, err := store.GetRefreshToken(tc.input)
			// Returns "not found" — the hash-based path is always safe
			assert.Error(t, err)
			assertNoEscape(t, dir, "refresh_tokens")
		})
	}
}

// =============================================================================
// File Permissions
// These tests FAIL before the fix — directories use 0755, files use umask.
// =============================================================================

// TestSecurity_DirPermissions verifies that storage directories are created
// with 0700 (owner-only access), not the default 0755 which allows other
// users on the system to list directory contents.
func TestSecurity_DirPermissions(t *testing.T) {
	dir := t.TempDir()

	// Create a user to trigger directory creation
	userStore := NewFSUserStore(dir)
	_, err := userStore.CreateUser("testuser", true, map[string]any{"name": "test"})
	require.NoError(t, err)

	// Check the users/ directory permissions
	usersDir := filepath.Join(dir, "users")
	info, err := os.Stat(usersDir)
	require.NoError(t, err)

	perm := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0700), perm,
		"users/ directory should be 0700 (owner-only), got %04o", perm)
}

// TestSecurity_FilePermissions verifies that data files are created with
// 0600 (owner read/write only), not the umask default (typically 0644)
// which allows other users to read sensitive data like password hashes.
func TestSecurity_FilePermissions(t *testing.T) {
	dir := t.TempDir()

	// Create a user file
	userStore := NewFSUserStore(dir)
	_, err := userStore.CreateUser("testuser", true, map[string]any{"name": "test"})
	require.NoError(t, err)

	// Check the file permissions
	userFile := filepath.Join(dir, "users", "testuser.json")
	info, err := os.Stat(userFile)
	require.NoError(t, err)

	perm := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), perm,
		"user data file should be 0600 (owner-only), got %04o", perm)
}

// TestSecurity_KeyFilePermissions verifies that key files containing
// signing secrets are created with 0600 permissions.
func TestSecurity_KeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	store := NewFSKeyStore(dir)

	err := store.PutKey(&keys.KeyRecord{
		ClientID:  "testapp",
		Key:       []byte("super-secret-key"),
		Algorithm: "HS256",
	})
	require.NoError(t, err)

	// Find the key file (FSKeyStore uses "signing_keys" subdirectory)
	keyFile := filepath.Join(dir, "signing_keys", "testapp.json")
	info, err := os.Stat(keyFile)
	require.NoError(t, err)

	perm := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), perm,
		"key file should be 0600 (owner-only), got %04o", perm)
}

// =============================================================================
// safeName unit tests
// =============================================================================

// TestSafeName verifies the shared input sanitizer rejects all known
// path traversal vectors and accepts clean inputs.
func TestSafeName(t *testing.T) {
	// These must be rejected
	rejectCases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"dot_dot", ".."},
		{"traversal", "../../etc/passwd"},
		{"backslash_traversal", "..\\..\\etc\\passwd"},
		{"null_byte", "foo\x00bar"},
		{"absolute_path", "/etc/passwd"},
		{"dot_dot_slash", "../"},
		{"embedded_dot_dot", "foo/../bar"},
		{"dot", "."},
	}

	for _, tc := range rejectCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			_, err := safeName(tc.input)
			assert.Error(t, err, "safeName should reject %q", tc.input)
		})
	}

	// These must be accepted and sanitized
	acceptCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "myapp", "myapp"},
		{"with_dash", "my-app", "my-app"},
		{"with_underscore", "my_app", "my_app"},
		{"with_dot", "my.app", "my.app"},
		{"email_key", "email:user@example.com", "email_user@example.com"},
		{"slash_to_underscore", "foo/bar", "foo_bar"},
		{"at_sign", "user@host", "user@host"},
		{"oa_prefix", "oa_abc123def456", "oa_abc123def456"},
	}

	for _, tc := range acceptCases {
		t.Run("accept_"+tc.name, func(t *testing.T) {
			result, err := safeName(tc.input)
			assert.NoError(t, err, "safeName should accept %q", tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// Helpers
// =============================================================================

// assertNoEscape verifies that no files were created outside the expected
// subdirectory of the storage root. This catches path traversal attacks
// that would write files to parent directories.
func assertNoEscape(t *testing.T, storageRoot, subdir string) {
	t.Helper()
	// Walk the temp dir parent to check for escaped files
	parent := filepath.Dir(storageRoot)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(storageRoot) {
			// Check if this is a file that shouldn't be here
			fullPath := filepath.Join(parent, e.Name())
			if _, err := os.Stat(fullPath); err == nil {
				// File exists outside our storage root — potential escape
				// Only flag .json files (our data files)
				if filepath.Ext(e.Name()) == ".json" {
					t.Errorf("SECURITY: file %q created outside storage root (path traversal escape)", fullPath)
				}
			}
		}
	}
}
