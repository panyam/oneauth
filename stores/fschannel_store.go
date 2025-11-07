package stores

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	oa "github.com/panyam/oneauth"
)

// FSChannelStore stores channels as JSON files
type FSChannelStore struct {
	StoragePath string
}

func NewFSChannelStore(storagePath string) *FSChannelStore {
	return &FSChannelStore{StoragePath: storagePath}
}

func (s *FSChannelStore) getChannelPath(provider, identityKey string) string {
	// Create safe filename from provider and identity key
	safeKey := strings.ReplaceAll(identityKey, ":", "_")
	safeKey = strings.ReplaceAll(safeKey, "/", "_")
	filename := fmt.Sprintf("%s_%s.json", provider, safeKey)
	return filepath.Join(s.StoragePath, "channels", filename)
}

func (s *FSChannelStore) GetChannel(provider string, identityKey string, createIfMissing bool) (*oa.Channel, bool, error) {
	path := s.getChannelPath(provider, identityKey)
	data, err := os.ReadFile(path)

	if err != nil {
		if os.IsNotExist(err) && createIfMissing {
			channel := &oa.Channel{
				Provider:    provider,
				IdentityKey: identityKey,
				Credentials: make(map[string]any),
				Profile:     make(map[string]any),
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			if err := s.SaveChannel(channel); err != nil {
				return nil, false, err
			}
			return channel, true, nil
		}
		if os.IsNotExist(err) {
			return nil, false, fmt.Errorf("channel not found")
		}
		return nil, false, err
	}

	var channel oa.Channel
	if err := json.Unmarshal(data, &channel); err != nil {
		return nil, false, err
	}
	return &channel, false, nil
}

func (s *FSChannelStore) SaveChannel(channel *oa.Channel) error {
	path := s.getChannelPath(channel.Provider, channel.IdentityKey)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	channel.UpdatedAt = time.Now()
	if channel.CreatedAt.IsZero() {
		channel.CreatedAt = time.Now()
	}

	data, err := json.MarshalIndent(channel, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}

func (s *FSChannelStore) GetChannelsByIdentity(identityKey string) ([]*oa.Channel, error) {
	channelsDir := filepath.Join(s.StoragePath, "channels")
	entries, err := os.ReadDir(channelsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*oa.Channel{}, nil
		}
		return nil, err
	}

	var channels []*oa.Channel
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(channelsDir, entry.Name()))
		if err != nil {
			continue
		}

		var channel oa.Channel
		if err := json.Unmarshal(data, &channel); err != nil {
			continue
		}

		if channel.IdentityKey == identityKey {
			channels = append(channels, &channel)
		}
	}

	return channels, nil
}
