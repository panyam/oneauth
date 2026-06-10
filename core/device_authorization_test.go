package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestDeviceAuthorization_IsExpired pins the pure-helper expiry check.
// Kept here (not in the shared contract suite) because it tests the
// DeviceAuthorization value type, not the DeviceAuthorizationStore
// interface — every backend reuses the same struct.
func TestDeviceAuthorization_IsExpired(t *testing.T) {
	now := time.Now()
	a := &DeviceAuthorization{ExpiresAt: now.Add(time.Minute)}
	assert.False(t, a.IsExpired(now))
	a.ExpiresAt = now.Add(-time.Second)
	assert.True(t, a.IsExpired(now))
}

// TestUpperUserCode_NormalizesCaseAndStripsDashes pins the single
// source of truth for RFC 8628 user_code normalization. Every
// DeviceAuthorizationStore backend resolves to this function via
// core.UpperUserCode, so this test now covers all four backends.
func TestUpperUserCode_NormalizesCaseAndStripsDashes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"WDJB-MJHT", "WDJBMJHT"},
		{"wdjb mjht", "WDJBMJHT"},
		{"WdJb-MjHt", "WDJBMJHT"},
		{"", ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, UpperUserCode(tc.in), tc.in)
	}
}
