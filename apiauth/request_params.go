package apiauth

import (
	"net/http"
	"net/url"
	"sort"
)

// repeatableParams may appear more than once in a request. RFC 8707 §2
// lets a client name several resources, and RFC 8693 §2.1 several
// audiences; the SDK sends both repeated.
var repeatableParams = map[string]bool{"resource": true, "audience": true}

// clientCredentialParams carry a client's secret or assertion. RFC 6749
// §2.3.1 says they MUST NOT be included in the request URI, since URIs
// end up in logs and browser history.
var clientCredentialParams = []string{"client_secret", "client_assertion", "client_assertion_type"}

// repeatedParam returns the name of a parameter sent more than once, or ""
// when there is none. RFC 6749 §3.1 and §3.2 say request parameters MUST
// NOT be included more than once; taking the first value would let two
// parties read one request differently. When several repeat, the first
// by name is reported, so the error is stable.
func repeatedParam(values url.Values) string {
	var names []string
	for k, vs := range values {
		if len(vs) > 1 && !repeatableParams[k] {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}

// checkFormParams vets a parsed form request to a token-side endpoint
// (token, introspection, revocation, device authorization, PAR). It
// refuses client credentials in the request URI and repeated body
// parameters with invalid_request. r.ParseForm must already have run.
func checkFormParams(r *http.Request) *GrantError {
	query := r.URL.Query()
	for _, p := range clientCredentialParams {
		if query.Has(p) {
			return invalidRequest(p + " must not be sent in the request URI (RFC 6749 §2.3.1); send it in the request body")
		}
	}
	if p := repeatedParam(r.PostForm); p != "" {
		return invalidRequest(p + " must not be included more than once (RFC 6749 §3.2)")
	}
	return nil
}
