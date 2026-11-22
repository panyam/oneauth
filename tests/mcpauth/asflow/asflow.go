// Package asflow drives the MCP conformance framework's authorization-server
// scenarios against oneauth-server without a person at a browser (issue 496).
//
// The framework's `authorization` command prints an authorization URL for
// each scenario that runs the code flow, then waits for a browser to bring
// the redirect to its callback server on 127.0.0.1. Watch reads the
// command's output, and hands each such URL to an approver. The approver is
// client.ApproveConsent on a client whose cookie jar holds the session that
// testutil.SignUp started. So it approves the consent page and follows the redirect
// to the callback, as the person would.
package asflow

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/panyam/oneauth/testutil"
)

// ClientMetadata is the RFC 7591 body Register sends: a public client that
// uses PKCE, with the framework's callback as its one redirect URI.
func ClientMetadata(redirectURI string) map[string]any {
	return map[string]any{
		"client_name":                "MCP conformance (authorization server suite)",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      "read",
	}
}

// Register registers ClientMetadata(redirectURI) through the server's open
// DCR endpoint and returns the client_id.
func Register(hc *http.Client, serverURL, redirectURI string) (string, error) {
	return testutil.RegisterClient(hc, serverURL+"/apps/dcr", ClientMetadata(redirectURI))
}

// Watch copies the command's output r to w line by line. A line that starts
// with authorizationEndpoint and a "?" is an authorization URL the framework
// wants a browser to open, and Watch passes it to approve. The framework's
// wording around the URL isn't a contract, so Watch keys on the endpoint
// from the AS metadata alone.
//
// The scenario blocks until its callback arrives, so approve runs in its own
// goroutine. Watch returns once r ends, with the URLs it saw and the first
// approval error.
func Watch(r io.Reader, w io.Writer, authorizationEndpoint string, approve func(string) error) ([]string, error) {
	var seen []string
	errs := make(chan error, 16)
	pending := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintln(w, line)
		u := strings.TrimSpace(line)
		if !strings.HasPrefix(u, authorizationEndpoint+"?") {
			continue
		}
		seen = append(seen, u)
		pending++
		go func(u string) { errs <- approve(u) }(u)
	}
	var first error
	for ; pending > 0; pending-- {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	if err := sc.Err(); err != nil && first == nil {
		first = err
	}
	return seen, first
}
