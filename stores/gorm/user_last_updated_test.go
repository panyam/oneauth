package gorm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
)

// GORM users report when the row last changed, which OIDC's updated_at
// claim reports (accounts.LastUpdatedUser, issue 480).
func TestGORMUser_ReportsLastUpdated(t *testing.T) {
	store := NewUserStore(setupTestDB(t))
	before := time.Now().Add(-time.Second)
	_, err := store.CreateUser(context.Background(), &accounts.CreateUserRequest{UserID: "u-480", IsActive: true, Profile: map[string]any{"username": "ada"}})
	require.NoError(t, err)
	resp, err := store.GetUserById(context.Background(), &accounts.GetUserByIDRequest{UserID: "u-480"})
	require.NoError(t, err)
	stamped, ok := resp.User.(accounts.LastUpdatedUser)
	require.True(t, ok)
	assert.True(t, stamped.LastUpdated().After(before), "LastUpdated %v", stamped.LastUpdated())
}
