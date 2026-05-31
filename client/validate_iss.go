package client

import (
	"errors"
	"fmt"
	"strings"
)

// ErrIssMismatch is returned by ValidateIss when the RFC 9207 `iss` query
// parameter is present on an authorization response but does not equal the
// expected authorization-server issuer (after RFC 3986 §6.2 normalization).
// A mismatch is the canonical mix-up-attack signal — a different AS is
// trying to convince the client to exchange a code against the wrong token
// endpoint. The flow MUST be aborted.
//
// See: https://www.rfc-editor.org/rfc/rfc9207#section-2.4
var ErrIssMismatch = errors.New("RFC 9207 iss does not match authorization server issuer")

// ErrIssMissing is returned by ValidateIss when the RFC 9207 `iss` query
// parameter is absent from the authorization response under conditions
// that require its presence — either because the AS metadata advertised
// support (so a missing iss is a spec violation), or because strict mode
// demands enforcement regardless of metadata (FAPI 2.0 / Open Banking /
// high-assurance regimes).
//
// See: https://www.rfc-editor.org/rfc/rfc9207#section-2.4
var ErrIssMissing = errors.New("RFC 9207 iss missing from authorization response")

// ValidateIss applies the RFC 9207 §2.4 enforcement rules to an `iss`
// query parameter received on an authorization-response redirect.
//
// Parameters:
//
//   - iss: the value of the `iss` query parameter from the redirect URL
//     (empty string when the AS did not include it).
//   - expectedIssuer: the issuer identifier the client expects (from
//     ASMetadata.Issuer or the configured trust anchor).
//   - asAdvertisedSupport: whether the AS metadata document advertised
//     `authorization_response_iss_parameter_supported: true`. Callers reading
//     from `client.ASMetadata.AuthorizationResponseIssParameterSupported`
//     (a `*bool`) should collapse the tristate at the call site:
//     `meta.AuthorizationResponseIssParameterSupported != nil && *meta.…`.
//   - strict: when true, an empty iss is always rejected regardless of
//     `asAdvertisedSupport`. Use for FAPI 2.0 / Open Banking / regulated
//     industries that mandate iss enforcement even against pre-9207 ASes.
//
// Truth table:
//
//	iss     | advertised | strict | result
//	--------|------------|--------|-----------------
//	matches | any        | any    | nil (accept)
//	differs | any        | any    | ErrIssMismatch
//	empty   | true       | any    | ErrIssMissing
//	empty   | false      | false  | nil (legacy AS — accept)
//	empty   | false      | true   | ErrIssMissing (strict)
//
// Issuer comparison normalizes both sides per RFC 3986 §6.2 syntax-based
// rules: scheme and host are lowercased; a single trailing slash on the
// issuer is ignored. Path segments beyond that are compared verbatim
// (per spec, path segments are case-sensitive and significant).
//
// Returns nil on accept, or a sentinel error (ErrIssMismatch /
// ErrIssMissing). Sentinel errors are safe to inspect via errors.Is.
//
// Calling with an empty expectedIssuer is a programmer error and returns
// a non-sentinel error — there is no defensible accept/reject decision
// when the trust anchor is unset.
//
// See: https://www.rfc-editor.org/rfc/rfc9207#section-2.4
func ValidateIss(iss, expectedIssuer string, asAdvertisedSupport, strict bool) error {
	if expectedIssuer == "" {
		return fmt.Errorf("ValidateIss: expectedIssuer must be non-empty")
	}

	if iss == "" {
		if asAdvertisedSupport || strict {
			return ErrIssMissing
		}
		return nil
	}

	if normalizeIssuer(iss) != normalizeIssuer(expectedIssuer) {
		return fmt.Errorf("%w: got %q, expected %q", ErrIssMismatch, iss, expectedIssuer)
	}
	return nil
}

// normalizeIssuer applies the subset of RFC 3986 §6.2.2 syntax-based
// normalization rules relevant to OAuth issuer identifiers:
//
//   - scheme: lowercased (§6.2.2.1)
//   - host: lowercased (§6.2.2.1)
//   - path: a single trailing slash is stripped so "https://x/" and
//     "https://x" compare equal. Inner path segments are NOT normalized.
//
// Kept unexported because two follow-on consumers (audience comparison,
// PRM resource-id comparison) want the same primitive, and the shared
// helper is tracked as a separate ticket after mcpkit#380. Promoting
// this to the public surface prematurely would lock in semantics that
// the broader ticket may need to refine.
func normalizeIssuer(s string) string {
	s = strings.TrimRight(s, "/")
	schemeEnd := strings.Index(s, "://")
	if schemeEnd == -1 {
		return strings.ToLower(s)
	}
	scheme := strings.ToLower(s[:schemeEnd])
	rest := s[schemeEnd+3:]
	pathStart := strings.Index(rest, "/")
	if pathStart == -1 {
		return scheme + "://" + strings.ToLower(rest)
	}
	host := strings.ToLower(rest[:pathStart])
	path := rest[pathStart:]
	return scheme + "://" + host + path
}
