package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/panyam/oneauth/core"
)

// FSChannelStore stores channels as JSON files
type FSChannelStore struct {
	StoragePath string
}

func NewFSChannelStore(storagePath string) *FSChannelStore {
	return &FSChannelStore{StoragePath: storagePath}
}

func (s *FSChannelStore) getChannelPath(provider, identityKey string) (string, error) {
	safeProvider, err := safeName(provider)
	if err != nil {
		return "", fmt.Errorf("invalid provider: %w", err)
	}
	safeKey, err := safeName(identityKey)
	if err != nil {
		return "", fmt.Errorf("invalid identityKey: %w", err)
	}
	filename := fmt.Sprintf("%s_%s.json", safeProvider, safeKey)
	return filepath.Join(s.StoragePath, "channels", filename), nil
}

func (s *FSChannelStore) GetChannel(provider string, identityKey string, createIfMissing bool) (*core.Channel, bool, error) {
	path, err := s.getChannelPath(provider, identityKey)
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)

	if err != nil {
		if os.IsNotExist(err) && createIfMissing {
			now := time.Now()
			channel := &core.Channel{
				Provider:    provider,
				IdentityKey: identityKey,
				Credentials: make(map[string]any),
				Profile:     make(map[string]any),
				CreatedAt:   now,
				UpdatedAt:   now,
				Version:     1,
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

	var channel core.Channel
	if err := json.Unmarshal(data, &channel); err != nil {
		return nil, false, err
	}
	return &channel, false, nil
}

func (s *FSChannelStore) SaveChannel(channel *core.Channel) error {
	path, err := s.getChannelPath(channel.Provider, channel.IdentityKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	channel.UpdatedAt = time.Now()
	if channel.CreatedAt.IsZero() {
		channel.CreatedAt = time.Now()
		channel.Version = 1
	} else {
		channel.Version++
	}

	data, err := json.MarshalIndent(channel, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}

func (s *FSChannelStore) GetChannelsByIdentity(identityKey string) ([]*core.Channel, error) {
	channelsDir := filepath.Join(s.StoragePath, "channels")
	entries, err := os.ReadDir(channelsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*core.Channel{}, nil
		}
		return nil, err
	}

	var channels []*core.Channel
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(channelsDir, entry.Name()))
		if err != nil {
			continue
		}

		var channel core.Channel
		if err := json.Unmarshal(data, &channel); err != nil {
			continue
		}

		if channel.IdentityKey == identityKey {
			channels = append(channels, &channel)
		}
	}

	return channels, nil
}
