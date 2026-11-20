package apiauth

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// checkResources validates a request's RFC 8707 resource indicators against
// allowed and returns the ones the token is bound to. With an empty
// allowlist the indicators are ignored, as they were before the AS
// supported them, and the result is nil. Otherwise each must be an absolute
// URI without a fragment (§2) that allowed lists exactly, or the request is
// invalid_target.
func checkResources(allowed, requested []string) ([]string, *GrantError) {
	if len(allowed) == 0 || len(requested) == 0 {
		return nil, nil
	}
	for _, r := range requested {
		u, err := url.Parse(r)
		if err != nil || !u.IsAbs() || strings.Contains(r, "#") {
			return nil, invalidTarget("resource " + r + " is not an absolute URI without a fragment")
		}
		if !slices.Contains(allowed, r) {
			return nil, invalidTarget("this authorization server issues no tokens for resource " + r)
		}
	}
	return requested, nil
}

// narrowResources returns the resources a token request may bind its token
// to, given the ones the grant was authorized for. A request naming none
// gets all of granted. One naming any outside granted is invalid_target,
// since RFC 8707 §2.2 lets a token request narrow the grant but not widen
// it.
func narrowResources(requested, granted []string) ([]string, *GrantError) {
	if len(requested) == 0 {
		return granted, nil
	}
	for _, r := range requested {
		if !slices.Contains(granted, r) {
			return nil, invalidTarget("resource " + r + " was not part of this grant")
		}
	}
	return requested, nil
}

func invalidTarget(desc string) *GrantError {
	return &GrantError{Code: "invalid_target", Description: desc, Status: http.StatusBadRequest}
}
