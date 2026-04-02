package fs

import (
	"fmt"
	"os"
	"path/filepath"
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

	// Reject absolute paths
	if filepath.IsAbs(input) {
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

	return safe, nil
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
