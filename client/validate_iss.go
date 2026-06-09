package client

import (
	"errors"
	"fmt"
)

// ErrIssMismatch is returned by ValidateIss when the RFC 9207 `iss` query
// parameter is present on an authorization response but does not byte-equal
// the expected authorization-server issuer identifier. A mismatch is the
// canonical mix-up-attack signal — a different AS is trying to convince the
// client to exchange a code against the wrong token endpoint. The flow MUST
// be aborted.
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
// Comparison is byte-for-byte. RFC 9207 §2.4 inherits comparison semantics
// from the JWT `iss` claim defined in RFC 9068 §2.1.1, which is byte-equal —
// not RFC 3986 §6.2 syntax-based URL normalization. Concretely:
//
//   - "https://auth.example.com" and "https://auth.example.com/" are
//     DIFFERENT issuers (trailing slash is significant).
//   - "https://auth.example.com" and "HTTPS://auth.example.com" are
//     DIFFERENT issuers (scheme case is significant).
//
// The MCP conformance scenario `sep-2468-client-no-normalization` (check
// id `auth/iss-normalized` in modelcontextprotocol/conformance) grades to
// exactly this rule: any normalization a client applies will fail the
// scenario.
//
// Returns nil on accept, or a sentinel error (ErrIssMismatch /
// ErrIssMissing). Sentinel errors are safe to inspect via errors.Is.
//
// Calling with an empty expectedIssuer is a programmer error and returns
// a non-sentinel error — there is no defensible accept/reject decision
// when the trust anchor is unset.
//
// See: https://www.rfc-editor.org/rfc/rfc9207#section-2.4
// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.1.1
// See: https://github.com/modelcontextprotocol/conformance (auth/iss-normalized)
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

	if iss != expectedIssuer {
		return fmt.Errorf("%w: got %q, expected %q", ErrIssMismatch, iss, expectedIssuer)
	}
	return nil
}
