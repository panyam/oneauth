package fs

import (
	"encoding/json"
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

// windowsDeviceNames are the names Windows opens as a device, whatever
// extension follows them, so "con.json" is the console.
var windowsDeviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM0": true, "COM1": true, "COM2": true, "COM3": true, "COM4": true,
	"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"COM¹": true, "COM²": true, "COM³": true,
	"LPT0": true, "LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
	"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	"LPT¹": true, "LPT²": true, "LPT³": true,
}

// osFileName makes name usable as a file name on the host OS. On Unix it
// returns name unchanged, so existing stores keep their file names. On
// Windows it replaces the characters Windows refuses with "_", and puts "_"
// in front of a device name such as CON or COM1. Two names can then map to
// one file, and the stores catch that with ErrKeyCollision. See issues 502
// and 505.
func osFileName(name string) string {
	if runtime.GOOS != "windows" {
		return name
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(windowsReserved, r) {
			return '_'
		}
		return r
	}, name)
	stem, _, _ := strings.Cut(name, ".")
	if windowsDeviceNames[strings.ToUpper(strings.TrimRight(stem, " "))] {
		name = "_" + name
	}
	return name
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

// ErrKeyCollision is returned by an FS store when the file a key maps to
// holds a different key's record. File names are derived from keys
// (filepath.Base, safeName, osFileName), and a case-insensitive file system
// also ignores letter case, so two keys can map to one file. Returning,
// overwriting or deleting the other record would hand one account's
// identity, credentials or keys to another (CWE-706).
var ErrKeyCollision = errors.New("fs: key maps to a file that holds a different record")

// readKeyed reads the JSON record at path and checks that keyOf returns want
// for it. It returns (nil, nil) when no file exists, and ErrKeyCollision
// when the file holds another key's record. Keys fold into one file name
// through safeName and osFileName, and on a case-insensitive file system
// (Windows, and macOS by default) through letter case too. See issue 505.
func readKeyed[T any](path, want string, keyOf func(*T) string) (*T, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec := new(T)
	if err := json.Unmarshal(data, rec); err != nil {
		return nil, err
	}
	if keyOf(rec) != want {
		return nil, ErrKeyCollision
	}
	return rec, nil
}

// checkOwner returns ErrKeyCollision when path holds another key's record,
// so a write or a delete for want can't replace or remove it. A missing or
// unreadable file is not a collision, and the caller may overwrite it.
func checkOwner[T any](path, want string, keyOf func(*T) string) error {
	if _, err := readKeyed(path, want, keyOf); errors.Is(err, ErrKeyCollision) {
		return err
	}
	return nil
}
