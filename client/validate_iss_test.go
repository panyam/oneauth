package client

// Tests for ValidateIss — the RFC 9207 §2.4 enforcement helper that
// consumers wire into BrowserLoginRequest.OnCallback.
//
// References:
//   - RFC 9207 §2.4 (https://www.rfc-editor.org/rfc/rfc9207#section-2.4):
//     "Comparing the iss Parameter Value with the Issuer Identifier"
//   - RFC 9068 §2.1.1 (https://www.rfc-editor.org/rfc/rfc9068#section-2.1.1):
//     the byte-equal JWT iss-claim comparison RFC 9207 inherits.
//   - MCP conformance check `auth/iss-normalized`
//     (https://github.com/modelcontextprotocol/conformance):
//     "Client MUST NOT apply scheme/host case folding, default-port elision,
//     trailing-slash, or percent-encoding normalization to iss before
//     comparison; a trailing-slash variant of the issuer must be treated as
//     a mismatch."

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateIss_TruthTable(t *testing.T) {
	const expected = "https://auth.example.com"

	cases := []struct {
		name            string
		iss             string
		expected        string
		advertised      bool
		strict          bool
		wantErr         error // nil, ErrIssMismatch, or ErrIssMissing
		wantNonSentinel bool  // expectedIssuer="" misuse
	}{
		{"match_exact", expected, expected, true, false, nil, false},
		{"match_advertised_false", expected, expected, false, false, nil, false},
		{"match_strict", expected, expected, false, true, nil, false},

		{"mismatch_different_host", "https://attacker.example.com", expected, true, false, ErrIssMismatch, false},
		{"mismatch_different_scheme", "http://auth.example.com", expected, false, false, ErrIssMismatch, false},
		{"mismatch_different_port", "https://auth.example.com:8443", expected, true, true, ErrIssMismatch, false},
		{"mismatch_different_path", "https://auth.example.com/other", expected, false, true, ErrIssMismatch, false},

		{"empty_iss_advertised_true_nonstrict_rejects", "", expected, true, false, ErrIssMissing, false},
		{"empty_iss_advertised_true_strict_rejects", "", expected, true, true, ErrIssMissing, false},
		{"empty_iss_advertised_false_nonstrict_accepts_legacy", "", expected, false, false, nil, false},
		{"empty_iss_advertised_false_strict_rejects", "", expected, false, true, ErrIssMissing, false},

		{"empty_expected_is_misuse", "https://auth.example.com", "", false, false, nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIss(tc.iss, tc.expected, tc.advertised, tc.strict)
			if tc.wantNonSentinel {
				require.Error(t, err)
				assert.NotErrorIs(t, err, ErrIssMismatch)
				assert.NotErrorIs(t, err, ErrIssMissing)
				assert.Contains(t, err.Error(), "expectedIssuer")
				return
			}
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestValidateIss_NoNormalization_RejectsEquivalents pins the byte-strict
// rule. Inputs that would have been accepted under the prior RFC 3986 §6.2
// normalization MUST now reject — RFC 9207 §2.4 inherits RFC 9068 §2.1.1's
// byte-equal comparison, not URL normalization. Same cases as the
// pre-#246 TestValidateIss_Normalization, assertion flipped from accept
// to reject; ensures the regression is locked in by test, not just by
// code change.
func TestValidateIss_NoNormalization_RejectsEquivalents(t *testing.T) {
	cases := []struct {
		name     string
		iss      string
		expected string
	}{
		{"trailing_slash_on_iss", "https://auth.example.com/", "https://auth.example.com"},
		{"trailing_slash_on_expected", "https://auth.example.com", "https://auth.example.com/"},
		{"trailing_slash_on_both_with_extra_slash", "https://auth.example.com//", "https://auth.example.com/"},
		{"scheme_case_on_iss", "HTTPS://auth.example.com", "https://auth.example.com"},
		{"host_case_on_iss", "https://AUTH.EXAMPLE.COM", "https://auth.example.com"},
		{"host_case_on_expected", "https://auth.example.com", "https://AUTH.example.com"},
		{"mixed_case_both_sides", "HTTPS://Auth.Example.Com/", "https://auth.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIss(tc.iss, tc.expected, true, true)
			require.Error(t, err, "byte-strict comparison MUST reject normalized equivalents")
			assert.ErrorIs(t, err, ErrIssMismatch)
		})
	}
}

// TestValidateIss_MCPConformance_TrailingSlashRejected uses the exact
// data from the MCP conformance failure mode captured in mcpkit's
// UPSTREAM_AUDIT: an AS that records its issuer as `http://localhost:N`
// but echoes `http://localhost:N/` in the redirect MUST be flagged.
func TestValidateIss_MCPConformance_TrailingSlashRejected(t *testing.T) {
	err := ValidateIss(
		"http://localhost:59958/",
		"http://localhost:59958",
		true, false,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIssMismatch)
}

func TestValidateIss_PortAndPathPreserved(t *testing.T) {
	// Port and path differences were already enforced before #246 and
	// remain so — included here as regression coverage so a future
	// refactor cannot silently re-introduce normalization there either.
	cases := []struct {
		name     string
		iss      string
		expected string
	}{
		{"explicit_port_443_differs_from_default", "https://auth.example.com:443", "https://auth.example.com"},
		{"path_case_significant", "https://auth.example.com/Tenant1", "https://auth.example.com/tenant1"},
		{"path_extra_segment", "https://auth.example.com/a/b", "https://auth.example.com/a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIss(tc.iss, tc.expected, true, false)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrIssMismatch)
		})
	}
}

func TestValidateIss_ErrorMessageIncludesValues(t *testing.T) {
	err := ValidateIss("https://attacker.example.com", "https://auth.example.com", true, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrIssMismatch))
	assert.True(t,
		strings.Contains(err.Error(), "attacker.example.com") &&
			strings.Contains(err.Error(), "auth.example.com"),
		"mismatch error should surface both observed and expected issuers for forensics: %v", err)
}
