// Tests for AllowList.Resolve and EntraGroups, which fetch a person's
// groups from Microsoft Graph when Entra left them out of the ID token
// (issue 555).
package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/oauth2/oidc"
)

var overageClaims = map[string]any{"sub": "u-1", "_claim_names": map[string]any{"groups": "src1"}}

func staticGroups(calls *int, groups []string, err error) oidc.GroupsSource {
	return func(context.Context) ([]string, error) {
		*calls++
		return groups, err
	}
}

func TestAllowList_Resolve(t *testing.T) {
	list := oidc.AllowList{Groups: []string{"eng"}}

	t.Run("overage resolved to a member", func(t *testing.T) {
		calls := 0
		d, err := list.Resolve(context.Background(), overageClaims, staticGroups(&calls, []string{"ops", "eng"}, nil))
		require.NoError(t, err)
		assert.Equal(t, oidc.Decision{Allowed: true, Rule: oidc.RuleGroup, GroupsOverage: true}, d)
		assert.Equal(t, 1, calls)
	})
	t.Run("overage resolved to a non-member", func(t *testing.T) {
		calls := 0
		d, err := list.Resolve(context.Background(), overageClaims, staticGroups(&calls, []string{"ops"}, nil))
		require.NoError(t, err)
		assert.Equal(t, oidc.Decision{GroupsOverage: true}, d)
	})
	t.Run("source error refuses and returns the error", func(t *testing.T) {
		calls := 0
		boom := errors.New("boom")
		d, err := list.Resolve(context.Background(), overageClaims, staticGroups(&calls, nil, boom))
		assert.ErrorIs(t, err, boom)
		assert.Equal(t, oidc.Decision{GroupsOverage: true}, d)
	})
	t.Run("no call without overage", func(t *testing.T) {
		calls := 0
		d, err := list.Resolve(context.Background(), map[string]any{"groups": []any{"ops"}}, staticGroups(&calls, []string{"eng"}, nil))
		require.NoError(t, err)
		assert.False(t, d.Allowed)
		assert.Equal(t, 0, calls)
	})
	t.Run("no call when another rule admits", func(t *testing.T) {
		calls := 0
		l := oidc.AllowList{Groups: []string{"eng"}, Subjects: []string{"u-1"}}
		d, err := l.Resolve(context.Background(), overageClaims, staticGroups(&calls, []string{"eng"}, nil))
		require.NoError(t, err)
		assert.Equal(t, oidc.RuleSubject, d.Rule)
		assert.Equal(t, 0, calls)
	})
	t.Run("no call when the list has no groups", func(t *testing.T) {
		calls := 0
		l := oidc.AllowList{EmailDomains: []string{"example.com"}}
		_, err := l.Resolve(context.Background(), overageClaims, staticGroups(&calls, []string{"eng"}, nil))
		require.NoError(t, err)
		assert.Equal(t, 0, calls)
	})
	t.Run("nil source is Decide", func(t *testing.T) {
		d, err := list.Resolve(context.Background(), overageClaims, nil)
		require.NoError(t, err)
		assert.Equal(t, oidc.Decision{GroupsOverage: true}, d)
	})
}

// See: https://learn.microsoft.com/en-us/graph/api/directoryobject-getmemberobjects
func TestEntraGroups_CallsGraph(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1.0/me/getMemberObjects" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"@odata.context":"x","value":["g-eng","g-ops"]}`))
	}))
	defer srv.Close()

	src := oidc.EntraGroups{AccessToken: "graph-token", HTTPClient: srv.Client(), GraphURL: srv.URL + "/v1.0/"}
	groups, err := src.Groups(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"g-eng", "g-ops"}, groups)
	assert.Equal(t, map[string]any{"securityEnabledOnly": false}, gotBody)

	d, err := oidc.AllowList{Groups: []string{"g-ops"}}.Resolve(context.Background(), overageClaims, src.Groups)
	require.NoError(t, err)
	assert.True(t, d.Allowed)
}

func TestEntraGroups_Failures(t *testing.T) {
	for name, tc := range map[string]struct {
		status  int
		body    string
		wantErr string
	}{
		"403 from Graph":    {status: http.StatusForbidden, body: `{"error":{"code":"Authorization_RequestDenied"}}`, wantErr: "403"},
		"not JSON":          {status: http.StatusOK, body: `<html>`, wantErr: "parsing"},
		"no value array":    {status: http.StatusOK, body: `{"error":"x"}`, wantErr: "no value"},
		"value not strings": {status: http.StatusOK, body: `{"value":[1,2]}`, wantErr: "parsing"},
		"body too large":    {status: http.StatusOK, body: `{"value":["` + strings.Repeat("a", 4<<20) + `"]}`, wantErr: "over"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := oidc.EntraGroups{AccessToken: "t", HTTPClient: srv.Client(), GraphURL: srv.URL}.Groups(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	t.Run("no access token", func(t *testing.T) {
		_, err := oidc.EntraGroups{}.Groups(context.Background())
		assert.ErrorContains(t, err, "no access token")
	})
}
