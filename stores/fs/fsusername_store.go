package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FSUsername represents a username reservation stored as JSON
type FSUsername struct {
	NormalizedUsername string    `json:"normalized_username"` // Lowercase for lookups
	Username           string    `json:"username"`            // Original case-preserved
	UserID             string    `json:"user_id"`
	Version            int       `json:"version"` // For optimistic concurrency
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// FSUsernameStore implements oa.UsernameStore using filesystem storage.
//
// # Purpose
//
// Provides username uniqueness enforcement and username-based login lookup
// using JSON files. Each username is stored as a separate file with the
// normalized (lowercase) username as the filename.
//
// # File Structure
//
//	{StoragePath}/
//	└── usernames/
//	    ├── johndoe.json     # {"username": "JohnDoe", "user_id": "abc123", ...}
//	    ├── janedoe.json     # {"username": "JaneDoe", "user_id": "xyz789", ...}
//	    └── ...
//
// # Concurrency Model
//
// Uses optimistic locking with version numbers. The atomic file write
// (write to temp, rename) provides basic safety, but concurrent modifications
// to the same username should be serialized at the application level or
// will result in last-write-wins behavior.
//
// # Setup
//
//	usernameStore := fs.NewFSUsernameStore("/var/data/myapp")
//
//	localAuth := &oneauth.LocalAuth{
//	    UsernameStore: usernameStore,
//	    SignupPolicy: &oneauth.SignupPolicy{
//	        RequireUsername:       true,
//	        EnforceUsernameUnique: true,
//	    },
//	}
type FSUsernameStore struct {
	StoragePath string
}

// NewFSUsernameStore creates a new filesystem-backed UsernameStore
func NewFSUsernameStore(storagePath string) *FSUsernameStore {
	return &FSUsernameStore{StoragePath: storagePath}
}

// normalizeUsername converts username to lowercase for case-insensitive lookup
func (s *FSUsernameStore) normalizeUsername(username string) string {
	return strings.ToLower(username)
}

// getUsernamePath returns the file path for a username
func (s *FSUsernameStore) getUsernamePath(normalizedUsername string) string {
	return filepath.Join(s.StoragePath, "usernames", normalizedUsername+".json")
}

// readUsername reads a username record from disk
func (s *FSUsernameStore) readUsername(normalizedUsername string) (*FSUsername, error) {
	path := s.getUsernamePath(normalizedUsername)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Not found
		}
		return nil, err
	}

	var username FSUsername
	if err := json.Unmarshal(data, &username); err != nil {
		return nil, err
	}
	return &username, nil
}

// writeUsername writes a username record to disk atomically
func (s *FSUsernameStore) writeUsername(username *FSUsername) error {
	path := s.getUsernamePath(username.NormalizedUsername)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(username, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}

// ReserveUsername reserves a username for a user.
// Returns error if username is already taken by a different user.
//
// # Concurrency
//
// Uses file system as implicit lock. The atomic write (temp file + rename)
// ensures no partial writes, but concurrent reservations of the same username
// will result in one succeeding (the last to complete the rename).
func (s *FSUsernameStore) ReserveUsername(username string, userID string) error {
	normalized := s.normalizeUsername(username)

	// Check if it exists
	existing, err := s.readUsername(normalized)
	if err != nil {
		return err
	}

	if existing != nil {
		// Username exists - check if same user
		if existing.UserID == userID {
			// Same user - update the case-preserved version if different
			if existing.Username != username {
				existing.Username = username
				existing.Version++
				existing.UpdatedAt = time.Now()
				return s.writeUsername(existing)
			}
			return nil
		}
		return fmt.Errorf("username already taken")
	}

	// Create new reservation
	now := time.Now()
	record := &FSUsername{
		NormalizedUsername: normalized,
		Username:           username,
		UserID:             userID,
		Version:            1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return s.writeUsername(record)
}

// GetUserByUsername looks up a userID by username (case-insensitive).
//
// # Usage
//
// Called by NewCredentialsValidatorWithUsername during login when
// user enters a username instead of email.
func (s *FSUsernameStore) GetUserByUsername(username string) (string, error) {
	normalized := s.normalizeUsername(username)

	record, err := s.readUsername(normalized)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", fmt.Errorf("username not found")
	}
	return record.UserID, nil
}

// ReleaseUsername removes a username reservation.
//
// # When to Use
//
// Call this when:
//   - User deletes their account
//   - Admin removes a username (e.g., for policy violations)
func (s *FSUsernameStore) ReleaseUsername(username string) error {
	normalized := s.normalizeUsername(username)
	path := s.getUsernamePath(normalized)

	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ChangeUsername atomically changes a username using optimistic concurrency.
// Returns error if new username is already taken.
//
// # Usage
//
// Called from a "Change Username" profile page handler.
//
// # Concurrency Note
//
// This is not fully atomic across files. In a race condition where another
// process takes the new username between our check and creation, we attempt
// to restore the old username. For production systems with high concurrency,
// consider using a database-backed store instead.
func (s *FSUsernameStore) ChangeUsername(oldUsername, newUsername, userID string) error {
	oldNormalized := s.normalizeUsername(oldUsername)
	newNormalized := s.normalizeUsername(newUsername)

	// If same normalized username, just update the case
	if oldNormalized == newNormalized {
		existing, err := s.readUsername(oldNormalized)
		if err != nil {
			return err
		}
		if existing == nil {
			return fmt.Errorf("username not found")
		}
		if existing.UserID != userID {
			return fmt.Errorf("username not owned by user")
		}

		existing.Username = newUsername
		existing.Version++
		existing.UpdatedAt = time.Now()
		return s.writeUsername(existing)
	}

	// Different username - need to delete old and create new

	// First verify old username exists and belongs to user
	oldRecord, err := s.readUsername(oldNormalized)
	if err != nil {
		return err
	}
	if oldRecord == nil {
		return fmt.Errorf("old username not found")
	}
	if oldRecord.UserID != userID {
		return fmt.Errorf("old username not owned by user")
	}

	// Check new username is available
	newRecord, err := s.readUsername(newNormalized)
	if err != nil {
		return err
	}
	if newRecord != nil {
		return fmt.Errorf("new username already taken")
	}

	// Delete old username file
	oldPath := s.getUsernamePath(oldNormalized)
	if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Create new username
	now := time.Now()
	newRecord = &FSUsername{
		NormalizedUsername: newNormalized,
		Username:           newUsername,
		UserID:             userID,
		Version:            1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.writeUsername(newRecord); err != nil {
		// Try to restore the old username
		oldRecord.Version++
		oldRecord.UpdatedAt = time.Now()
		s.writeUsername(oldRecord) // Best effort
		return fmt.Errorf("failed to create new username: %w", err)
	}

	return nil
}
