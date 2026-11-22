package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GroupsSource fetches the signed-in person's groups from somewhere other
// than the ID token. Resolve calls it when the token left the groups claim
// out for overage. EntraGroups.Groups is one.
type GroupsSource func(ctx context.Context) ([]string, error)

// Resolve is Decide, followed by a fetch of the person's groups when
// overage hid them. It calls source only when four things hold: no rule
// matched, Decide reported GroupsOverage, the list has Groups to match,
// and source isn't nil. Otherwise it returns Decide's result without a
// network call.
//
// When source fails, Resolve returns the refusal from Decide, with
// GroupsOverage set, and the error. Treat that as a refusal: the person
// may still be a member, but nothing proved it.
func (a AllowList) Resolve(ctx context.Context, claims map[string]any, source GroupsSource) (Decision, error) {
	d := a.Decide(claims)
	if d.Allowed || !d.GroupsOverage || len(a.Groups) == 0 || source == nil {
		return d, nil
	}
	groups, err := source(ctx)
	if err != nil {
		return d, fmt.Errorf("oidc: resolving groups overage: %w", err)
	}
	if a.groupsMatch(groups) {
		d.Allowed, d.Rule = true, RuleGroup
	}
	return d, nil
}

// DefaultGraphURL is the Microsoft Graph v1.0 root EntraGroups calls when
// GraphURL is empty.
const DefaultGraphURL = "https://graph.microsoft.com/v1.0"

// maxGraphResponse caps the getMemberObjects body EntraGroups reads. A
// group ID is a 36-character GUID, so 4 MiB holds about 100,000 of them.
const maxGraphResponse = 4 << 20

// EntraGroups fetches a person's group IDs from Microsoft Graph with the
// access token from the same Entra ID sign-in. Pass its Groups method to
// AllowList.Resolve. The IDs match what Entra puts in the `groups` claim,
// so the same AllowList.Groups values work for both.
//
// The access token must be for Microsoft Graph, and the app registration
// must grant a delegated permission that lets the person read their own
// group memberships. Microsoft's getMemberObjects page lists which ones.
// Ask for the permission's scope in Config.Scopes beside "openid", so the
// sign-in's access token carries it.
type EntraGroups struct {
	// AccessToken is the sign-in's access token. HandleUser receives it
	// as token.AccessToken.
	AccessToken string

	// HTTPClient makes the Graph request. Nil uses http.DefaultClient.
	HTTPClient *http.Client

	// GraphURL replaces DefaultGraphURL, such as for a national cloud or
	// a test's fake server.
	GraphURL string
}

// Groups calls POST {GraphURL}/me/getMemberObjects with
// securityEnabledOnly false. Graph returns every group and directory role
// the person belongs to, directly or through nesting. That's a superset of
// the groups claim, whichever group types the app registration emits. A
// status other than 200, or a body that isn't the expected JSON, is an
// error.
func (e EntraGroups) Groups(ctx context.Context) ([]string, error) {
	if e.AccessToken == "" {
		return nil, fmt.Errorf("entra groups: no access token")
	}
	base := strings.TrimSuffix(e.GraphURL, "/")
	if base == "" {
		base = DefaultGraphURL
	}
	hc := e.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/me/getMemberObjects",
		bytes.NewReader([]byte(`{"securityEnabledOnly":false}`)))
	if err != nil {
		return nil, fmt.Errorf("entra groups: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("entra groups: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGraphResponse+1))
	if err != nil {
		return nil, fmt.Errorf("entra groups: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("entra groups: getMemberObjects returned %s", resp.Status)
	}
	if len(body) > maxGraphResponse {
		return nil, fmt.Errorf("entra groups: getMemberObjects response over %d bytes", maxGraphResponse)
	}
	var out struct {
		Value *[]string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("entra groups: parsing response: %w", err)
	}
	if out.Value == nil {
		return nil, fmt.Errorf("entra groups: response has no value array")
	}
	return *out.Value, nil
}
