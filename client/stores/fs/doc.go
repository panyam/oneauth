// Package fs provides a filesystem-backed credential store that persists
// oneauth client server credentials as a single JSON file keyed by
// normalized server URL.
//
// The package owns one type, FSCredentialStore, which keeps server
// credentials in an in-memory map guarded by a RWMutex and mirrors them to
// a JSON file on disk. Keys are normalized server URLs (scheme://host);
// the normalizer defaults a missing scheme to https and strips paths and
// queries so variant URLs collapse onto one entry. Mutations only touch
// memory and flip a modified flag — nothing is written until Save is
// called, which no-ops when unchanged and otherwise writes the directory
// at 0700 and the file at 0600 because the contents are secrets. The
// default path resolves to ~/.config/<appName>/credentials.json, falling
// back to ~/.config when UserConfigDir is unavailable and to "oneauth"
// when appName is empty. A missing file at construction is tolerated, so
// first-run callers get an empty but usable store.
//
// ENTITIES
//
// FSCredentialStore — in-memory map of server credentials backed by a
// JSON file, guarded by a RWMutex. Mutations stay in memory until Save
// so callers control when secrets touch disk.
//
// credentialFile — on-disk JSON shape wrapping the servers map under a
// "servers" key. Gives the file a single top-level object so the format
// can grow without breaking older readers.
//
// NewFSCredentialStore — constructs a store, defaulting the path to
// ~/.config/<appName>/credentials.json and eagerly loading any existing
// file. A missing file is not an error so first-run callers get an
// empty but usable store.
//
// normalizeURL — reduces a server URL to scheme://host, defaulting a
// missing scheme to https. Variant URLs (trailing slashes, paths,
// queries) collapse onto one credential entry.
//
// GetCredential — looks up a credential by normalized server URL.
// Returns (nil, nil) on a miss so callers must nil-check rather than
// relying on an error.
//
// SetCredential — stores a credential under its normalized URL key and
// marks the store dirty. Defers the file write to Save so callers can
// batch updates.
//
// RemoveCredential — deletes a credential by normalized URL key and
// marks the store dirty. Defers the file rewrite to Save, matching
// SetCredential's batching model.
//
// ListServers — returns all normalized server URL keys currently in
// the store. Callers see the canonical scheme://host form, not the
// original input strings.
//
// Save — persists the map to disk as indented JSON when modified.
// Creates the directory 0700 and file 0600 because the contents are
// secrets; no-ops when nothing changed.
//
// Path — returns the resolved path to the credentials file. After
// default-path resolution callers often need the actual location for
// logging or display.
//
// FLOWS
//
// See [diagrams.md](diagrams.md) for sequence diagrams of:
// construction with default-path resolution, and the mutate-then-Save
// write-back cycle.
package fs
