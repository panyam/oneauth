// Package fs provides a filesystem-backed credential store that persists
// oneauth client server credentials as a single JSON file keyed by normalized
// server URL.
//
// <!-- design:start -->
// The package owns one type, FSCredentialStore, which keeps server
// credentials in an in-memory map guarded by a RWMutex and mirrors them to a
// JSON file on disk. Keys are normalized server URLs (scheme://host); the
// normalizer defaults a missing scheme to https and strips paths/queries so
// that variant URLs collapse onto one entry. Mutations (Set, Remove) only
// touch memory and flip a modified flag — nothing is written until Save is
// called, which no-ops when unchanged and otherwise writes the directory at
// 0700 and the file at 0600 because the contents are secrets. The default
// path resolves to ~/.config/<appName>/credentials.json (falling back to
// ~/.config when UserConfigDir is unavailable, and to "oneauth" when appName
// is empty). A missing file at construction is tolerated, so first-run
// callers get an empty but usable store.
//
// # ENTITIES
//
// FSCredentialStore — in-memory map of server credentials backed by a JSON
// file, guarded by a RWMutex; mutations stay in memory until Save.
//
// NewFSCredentialStore — constructs a store, defaulting the path to
// ~/.config/<appName>/credentials.json and eagerly loading any existing file;
// a missing file is not an error.
//
// GetCredential — looks up a credential by normalized server URL; returns
// (nil, nil) on a miss, so callers must nil-check the credential.
//
// SetCredential — stores a credential under its normalized URL key and marks
// the store dirty; does not write to disk.
//
// RemoveCredential — deletes a credential by normalized URL key and marks the
// store dirty; defers the file rewrite to Save.
//
// ListServers — returns all normalized server URL keys (scheme://host), not
// the original input strings.
//
// Save — persists the map to disk as indented JSON if modified, creating the
// directory 0700 and file 0600; no-ops when nothing changed.
//
// Path — returns the resolved path to the credentials file after default-path
// resolution.
// <!-- design:end -->
package fs
