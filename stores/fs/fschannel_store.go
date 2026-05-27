package fs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/panyam/oneauth/accounts"
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

func (s *FSChannelStore) GetChannel(ctx context.Context, req *accounts.GetChannelRequest) (*accounts.GetChannelResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetChannel: req is required")
	}
	path, err := s.getChannelPath(req.Provider, req.IdentityKey)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)

	if err != nil {
		if os.IsNotExist(err) && req.CreateIfMissing {
			now := time.Now()
			channel := &accounts.Channel{
				Provider:    req.Provider,
				IdentityKey: req.IdentityKey,
				Credentials: make(map[string]any),
				Profile:     make(map[string]any),
				CreatedAt:   now,
				UpdatedAt:   now,
				Version:     1,
			}
			if _, err := s.SaveChannel(ctx, &accounts.SaveChannelRequest{Channel: channel}); err != nil {
				return nil, err
			}
			return &accounts.GetChannelResponse{Channel: channel, NewCreated: true}, nil
		}
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("channel not found")
		}
		return nil, err
	}

	var channel accounts.Channel
	if err := json.Unmarshal(data, &channel); err != nil {
		return nil, err
	}
	return &accounts.GetChannelResponse{Channel: &channel}, nil
}

func (s *FSChannelStore) SaveChannel(ctx context.Context, req *accounts.SaveChannelRequest) (*accounts.SaveChannelResponse, error) {
	if req == nil || req.Channel == nil {
		return nil, fmt.Errorf("SaveChannel: req.Channel is required")
	}
	channel := req.Channel
	path, err := s.getChannelPath(channel.Provider, channel.IdentityKey)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
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
		return nil, err
	}
	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}
	return &accounts.SaveChannelResponse{}, nil
}

func (s *FSChannelStore) GetChannelsByIdentity(ctx context.Context, req *accounts.GetChannelsByIdentityRequest) (*accounts.GetChannelsByIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetChannelsByIdentity: req is required")
	}
	channelsDir := filepath.Join(s.StoragePath, "channels")
	entries, err := os.ReadDir(channelsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &accounts.GetChannelsByIdentityResponse{Channels: []*accounts.Channel{}}, nil
		}
		return nil, err
	}

	var channels []*accounts.Channel
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(channelsDir, entry.Name()))
		if err != nil {
			continue
		}
		var channel accounts.Channel
		if err := json.Unmarshal(data, &channel); err != nil {
			continue
		}
		if channel.IdentityKey == req.IdentityKey {
			channels = append(channels, &channel)
		}
	}
	return &accounts.GetChannelsByIdentityResponse{Channels: channels}, nil
}
