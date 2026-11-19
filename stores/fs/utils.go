package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// safeName sanitizes user-supplied input before using it in filesystem paths.
// It rejects path traversal attacks (.., null bytes, absolute paths) and
// replaces dangerous characters (/, \, :) with underscores.
//
// Returns an error for any input that could escape the storage directory.
// This is the single point of defense for all FS store path construction.
func safeName(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty name")
	}

	// Reject null bytes (can truncate paths on some OSes)
	if strings.ContainsRune(input, '\x00') {
		return "", fmt.Errorf("name contains null byte")
	}

	// Reject absolute paths. A leading "/" or "\" counts on every OS: on
	// Windows filepath.IsAbs says no to "/etc/passwd", since it has no drive,
	// but the path is still rooted.
	if filepath.IsAbs(input) || strings.HasPrefix(input, "/") || strings.HasPrefix(input, `\`) {
		return "", fmt.Errorf("name is an absolute path")
	}

	// Replace dangerous path separators
	safe := strings.ReplaceAll(input, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	safe = strings.ReplaceAll(safe, ":", "_")

	// Use filepath.Base as a final guard — strips any remaining directory components
	safe = filepath.Base(safe)

	// Reject . and .. after sanitization
	if safe == "." || safe == ".." {
		return "", fmt.Errorf("name resolves to %q after sanitization", safe)
	}

	// Reject if the result contains ".." anywhere (embedded traversal like "foo/../bar")
	if strings.Contains(safe, "..") {
		return "", fmt.Errorf("name contains path traversal sequence")
	}

	return osFileName(safe), nil
}

// windowsReserved holds the characters Windows refuses in a file name.
const windowsReserved = `<>:"|?*`

// osFileName replaces the characters the host OS refuses in a file name
// with "_". On Unix it returns name unchanged, so existing stores keep their
// file names. On Windows two names can fold to one file, and the stores that
// take user-chosen keys check for that with ErrKeyCollision. See issue 502.
func osFileName(name string) string {
	if runtime.GOOS != "windows" {
		return name
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(windowsReserved, r) {
			return '_'
		}
		return r
	}, name)
}

// writeAtomicFile writes data to a file atomically by writing to a temp file first
func writeAtomicFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Write data to temp file
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomically rename temp file to target path
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	// Ensure restrictive permissions on the final file
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	return nil
}

// ErrKeyCollision is returned by the FS identity and channel stores when the
// file a key maps to holds a different key's record. File names are derived
// from keys (filepath.Base, safeName), and two keys can map to one name;
// returning or overwriting the other record would hand one account's
// identity or credentials to another (CWE-706).
var ErrKeyCollision = errors.New("fs: key maps to a file that holds a different record")
