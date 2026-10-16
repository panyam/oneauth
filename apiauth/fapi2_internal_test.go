package apiauth

// FAPI 2.0 §5.3.2.2 lifetimes: authorization codes at most 60 seconds,
// request_uris under 600. A longer configured value is capped; a shorter
// one, or the default, stands.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html

import (
	"testing"
	"time"
)

func TestFAPI2_LifetimeCaps(t *testing.T) {
	for _, c := range []struct {
		configured, max, want time.Duration
	}{
		{10 * time.Minute, fapi2MaxCodeLifetime, 60 * time.Second},
		{30 * time.Second, fapi2MaxCodeLifetime, 30 * time.Second},
		{0, fapi2MaxCodeLifetime, 0}, // the default, which is 60s already
		{time.Hour, fapi2MaxRequestURILifetime, fapi2MaxRequestURILifetime},
	} {
		if got := capLifetime(c.configured, c.max); got != c.want {
			t.Errorf("capLifetime(%v, %v) = %v, want %v", c.configured, c.max, got, c.want)
		}
	}
	if DefaultAuthorizationCodeExpiry > fapi2MaxCodeLifetime || DefaultPushedRequestExpiry > fapi2MaxRequestURILifetime {
		t.Errorf("a default is longer than FAPI allows")
	}
	if fapi2MaxRequestURILifetime >= 600*time.Second {
		t.Errorf("request_uri lifetime must be under 600s, got %v", fapi2MaxRequestURILifetime)
	}
}
