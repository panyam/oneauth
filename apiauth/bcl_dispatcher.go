package apiauth

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/panyam/oneauth/core"
)

// AppRegistrationLookup is the narrow read-only slice of admin.AppRegistrar
// that BCLDispatcher needs. Defined here (rather than importing admin/) to
// avoid a circular dependency — admin/ already imports apiauth/ transitively
// via the hooks layer in some configurations.
//
// Implementations: *admin.AppRegistrar satisfies this via RLockApps; tests can
// inject an in-memory map.
type AppRegistrationLookup interface {
	// GetAppRegistration returns the persisted registration for clientID, or
	// (nil, false) if no such client exists or its registration is being
	// torn down. Returning a clone is recommended so callers cannot mutate
	// store state through the returned pointer.
	GetAppRegistration(ctx context.Context, clientID string) (*core.AppRegistration, bool)
}

// BCLDispatcher pushes OIDC Back-Channel Logout 1.0 notifications to every
// client that registered a backchannel_logout_uri and has an active
// refresh-token grant for the affected subject.
//
// The dispatcher is intentionally narrow: callers tell it a session ended
// (Dispatch), it looks up the clients to notify, mints one logout_token per
// client, and POSTs each token to the registered URI. Dispatch is fire-and-
// forget by default — a slow or broken receiver MUST NOT stall the revocation
// path. Set SyncForTest=true to wait for all POSTs before returning (used by
// e2e tests; not recommended for production wiring).
//
// Retry / backoff: the spec is silent (§3.2 ¶3); this dispatcher does not
// retry on failure. Follow-ups can wrap HTTPClient with a retry transport.
type BCLDispatcher struct {
	// Issuer mints the signed logout_token. Required.
	Issuer LogoutTokenIssuer

	// Apps resolves a client_id to its registration so we can read
	// backchannel_logout_uri and backchannel_logout_session_required.
	// Required.
	Apps AppRegistrationLookup

	// RefreshStore enumerates a subject's active grants. Required for
	// subject-scoped Dispatch calls; ignored for explicit-client calls.
	RefreshStore core.RefreshTokenStore

	// HTTPClient is used for outbound POSTs. Defaults to an http.Client with
	// a 5-second per-request timeout so a stuck receiver cannot pin a
	// goroutine indefinitely.
	HTTPClient *http.Client

	// Logger receives non-fatal dispatch errors (4xx/5xx from receiver,
	// network failures, signing errors). If nil, log.Default() is used.
	Logger *log.Logger

	// SyncForTest makes Dispatch block until every POST completes. Tests use
	// this to assert the receiver was hit before they read its captured
	// state; production callers should leave it false so revocation latency
	// is not coupled to receiver responsiveness.
	SyncForTest bool

	// AllowPrivateHosts opts in to dialing receiver URIs whose resolved IP
	// is loopback / RFC1918 / link-local / unspecified / multicast. Off by
	// default — the default HTTPClient's dialer rejects such connections so
	// a (mis-configured or malicious) `backchannel_logout_uri` cannot be
	// used to make the AS POST to internal services on its behalf, even if
	// the hostname's DNS answer at dial time differs from registration time
	// (rebinding). Closed-network deployments (AS + RS in the same VPC) can
	// flip this on; admin.AppRegistrar.AllowPrivateBCLHosts is the matching
	// registration-side knob.
	AllowPrivateHosts bool

	// wg tracks in-flight async dispatches so callers (mainly tests) can
	// wait for them via Wait().
	wg sync.WaitGroup
}

// DispatchRequest is the input to BCLDispatcher.Dispatch.
//
// At least one of Subject and ClientIDs MUST be set:
//   - Subject only: enumerate every client with an active grant for that
//     subject via RefreshStore.GetSubjectTokens.
//   - ClientIDs only: notify exactly those clients; used for single-token
//     revoke where the affected client is known from the token itself.
//   - Both: union (notify the explicit clients plus any others holding active
//     grants for the subject).
type DispatchRequest struct {
	// Subject is the user identifier whose session ended.
	Subject string

	// SID is the OIDC session ID. oneauth maps this to the refresh-token
	// family ID; pass empty when no family-scoped revoke happened.
	SID string

	// ClientIDs names clients to notify directly. Useful when the trigger is
	// a single-token revoke and the AS already knows the client_id from the
	// token claims.
	ClientIDs []string
}

// DispatchResponse is empty — dispatch errors are logged, not returned, so a
// failing client cannot block the revocation path. The struct is preserved
// for forward-compat headroom (e.g., to expose per-client outcomes for
// telemetry without changing the method signature).
type DispatchResponse struct{}

// Dispatch resolves the affected client set, mints a logout_token per client,
// and POSTs each token to its registered backchannel_logout_uri.
//
// Returns nil immediately when no eligible client exists (no clients in the
// union, or none of them registered a BCL URI). Per-client errors are logged
// via Logger and otherwise swallowed: BCL is best-effort notification, not
// transactional with revocation.
func (d *BCLDispatcher) Dispatch(ctx context.Context, req *DispatchRequest) (*DispatchResponse, error) {
	if d == nil || req == nil {
		return &DispatchResponse{}, nil
	}
	if d.Issuer == nil || d.Apps == nil {
		return nil, fmt.Errorf("BCLDispatcher: Issuer and Apps are required")
	}

	clientIDs := map[string]struct{}{}
	for _, cid := range req.ClientIDs {
		if cid != "" {
			clientIDs[cid] = struct{}{}
		}
	}
	if req.Subject != "" && d.RefreshStore != nil {
		resp, err := d.RefreshStore.GetSubjectTokens(ctx, &core.GetSubjectTokensRequest{Subject: req.Subject})
		if err != nil {
			d.logger().Printf("bcl: GetSubjectTokens(%q): %v", req.Subject, err)
		} else if resp != nil {
			for _, t := range resp.Tokens {
				if t != nil && t.ClientID != "" {
					clientIDs[t.ClientID] = struct{}{}
				}
			}
		}
	}
	if len(clientIDs) == 0 {
		return &DispatchResponse{}, nil
	}

	for cid := range clientIDs {
		reg, ok := d.Apps.GetAppRegistration(ctx, cid)
		if !ok || reg == nil || reg.BackchannelLogoutURI == "" {
			continue
		}
		// Per §2.4 when the client opts in via backchannel_logout_session_required
		// the AS MUST include sid. If we don't have one (e.g. single-token revoke
		// without family context), skip rather than emit an invalid token.
		if reg.BackchannelLogoutSessionRequired && req.SID == "" {
			d.logger().Printf("bcl: skipping %q — session_required but no sid", cid)
			continue
		}
		tokReq := &CreateLogoutTokenRequest{
			Audience: cid,
			Subject:  req.Subject,
			SID:      req.SID,
		}
		tokResp, err := d.Issuer.CreateLogoutToken(ctx, tokReq)
		if err != nil {
			d.logger().Printf("bcl: mint token for %q: %v", cid, err)
			continue
		}
		uri := reg.BackchannelLogoutURI
		token := tokResp.Token
		if d.SyncForTest {
			d.post(ctx, cid, uri, token)
		} else {
			d.wg.Add(1)
			go func() {
				defer d.wg.Done()
				d.post(context.Background(), cid, uri, token)
			}()
		}
	}
	return &DispatchResponse{}, nil
}

// Wait blocks until every async POST started by Dispatch has finished. Tests
// use it as a barrier; production code that wants synchronous behavior should
// set SyncForTest instead.
func (d *BCLDispatcher) Wait() {
	if d == nil {
		return
	}
	d.wg.Wait()
}

// post is the unit of outbound work — one POST per (client, logout_token).
// Errors here cannot bubble to the caller (Dispatch is fire-and-forget by
// design); we log them and move on. The receiver is expected to return 2xx
// per §2.7 ¶2; anything else is treated as a dispatch failure.
func (d *BCLDispatcher) post(ctx context.Context, clientID, uri, token string) {
	body := strings.NewReader(url.Values{"logout_token": {token}}.Encode())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, body)
	if err != nil {
		d.logger().Printf("bcl: build request for %q: %v", clientID, err)
		return
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Cache-Control", "no-store")

	resp, err := d.httpClient().Do(httpReq)
	if err != nil {
		d.logger().Printf("bcl: POST %s: %v", uri, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		d.logger().Printf("bcl: receiver %s returned %d", uri, resp.StatusCode)
	}
}

func (d *BCLDispatcher) httpClient() *http.Client {
	if d.HTTPClient != nil {
		return d.HTTPClient
	}
	allowPrivate := d.AllowPrivateHosts
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("bcl: invalid dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("bcl: dial address %q is not a literal IP", address)
			}
			if isPrivateOrSpecialIP(ip) {
				return fmt.Errorf("bcl: refusing to dial private/loopback/link-local address %s", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		// Do NOT follow redirects. A 3xx to a different host (or to an
		// internal IP) would re-open the SSRF surface that the dial-time
		// guard closes for the registered URI itself. Receivers per OIDC
		// BCL §2.7 respond with 200 on success / 4xx-5xx on failure; a
		// 3xx is not part of the protocol and we let the dispatcher's
		// caller see it as the final status.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}
}

// isPrivateOrSpecialIP mirrors admin.isPrivateOrSpecialIP — duplicated rather
// than imported so apiauth/ stays free of an admin/ dependency. Any change
// to the SSRF policy must update both sites.
func isPrivateOrSpecialIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func (d *BCLDispatcher) logger() *log.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return log.Default()
}
