package deviceauthtest

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUserCodeLookupsOmitDeviceCode pins that Get and Approve by
// user_code leave DeviceCode empty, while the record stays linked: GetByDeviceCode after an approval or a denial sees it. Stores
// keep only core.AtRestKey(device_code), so a user_code path has no
// device_code to return.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-5.2
// See: https://cwe.mitre.org/data/definitions/312.html
func TestUserCodeLookupsOmitDeviceCode(t *testing.T, factory Factory) {
	s := factory(t).Store
	ctx := context.Background()
	createDeviceAuth(t, s, newAuth())

	approved, err := s.ApproveDeviceAuthorization(ctx, &core.ApproveDeviceAuthorizationRequest{UserCode: "WDJB-MJHT", ApprovedSubject: "user-1"})
	require.NoError(t, err)
	if approved != nil && approved.Authorization != nil {
		assert.Empty(t, approved.Authorization.DeviceCode, "Approve's response MUST NOT carry the device_code")
	}
	g, err := s.GetByDeviceCode(ctx, &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusApproved, g.Authorization.Status, "approval by user_code reaches the record keyed by device_code")
	assert.Equal(t, "dc-abc", g.Authorization.DeviceCode, "a device_code lookup returns the code it was asked for")

	other := newAuth()
	other.DeviceCode, other.UserCode = "dc-other", "BCDF-GHJK"
	createDeviceAuth(t, s, other)
	_, err = s.DenyDeviceAuthorization(ctx, &core.DenyDeviceAuthorizationRequest{UserCode: "BCDF-GHJK"})
	require.NoError(t, err)
	d, err := s.GetByDeviceCode(ctx, &core.GetByDeviceCodeRequest{DeviceCode: "dc-other"})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusDenied, d.Authorization.Status, "denial by user_code reaches the record keyed by device_code")
}

// TestConcurrentApproveOrDenyOneWins races four approvals and four
// denials of one pending authorization. The pending-to-final transition
// may happen once: one call succeeds and the rest get
// ErrDeviceAuthorizationNotFound, never a backend conflict error.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.3
// See: https://cwe.mitre.org/data/definitions/367.html
func TestConcurrentApproveOrDenyOneWins(t *testing.T, factory Factory) {
	s := factory(t).Store
	ctx := context.Background()
	createDeviceAuth(t, s, newAuth())

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	var ready sync.WaitGroup
	for i := range n {
		wg.Add(1)
		ready.Add(1)
		go func() {
			defer wg.Done()
			// A lookup first, so a pooled backend has a live connection per
			// goroutine; otherwise connection setup staggers the calls and
			// they rarely overlap.
			_, _ = s.GetByUserCode(ctx, &core.GetByUserCodeRequest{UserCode: "WDJB-MJHT"})
			ready.Done()
			<-start
			if i%2 == 0 {
				_, errs[i] = s.ApproveDeviceAuthorization(ctx, &core.ApproveDeviceAuthorizationRequest{UserCode: "WDJB-MJHT", ApprovedSubject: "user-1"})
			} else {
				_, errs[i] = s.DenyDeviceAuthorization(ctx, &core.DenyDeviceAuthorizationRequest{UserCode: "WDJB-MJHT"})
			}
		}()
	}
	ready.Wait()
	close(start)
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, core.ErrDeviceAuthorizationNotFound):
			t.Errorf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, wins, "exactly one approve or deny may take effect")
}
