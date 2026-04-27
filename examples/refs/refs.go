// Package refs provides pre-defined reference constants for OneAuth examples.
// These are project-specific (OAuth RFCs, CVEs) — the demokit framework itself
// is generic and lives at github.com/panyam/demokit.
package refs

import "github.com/panyam/demokit"

// OAuth 2.0
var (
	RFC6749                   = demokit.Ref{Name: "RFC 6749 — OAuth 2.0", URL: "https://www.rfc-editor.org/rfc/rfc6749"}
	RFC6749_ClientCredentials = demokit.Ref{Name: "RFC 6749 §4.4 — Client Credentials Grant", URL: "https://www.rfc-editor.org/rfc/rfc6749#section-4.4"}
	RFC6749_AuthorizationCode = demokit.Ref{Name: "RFC 6749 §4.1 — Authorization Code Grant", URL: "https://www.rfc-editor.org/rfc/rfc6749#section-4.1"}
	RFC6750                   = demokit.Ref{Name: "RFC 6750 — Bearer Token Usage", URL: "https://www.rfc-editor.org/rfc/rfc6750"}
)

// JWT / JWS / JWK
var (
	RFC7515 = demokit.Ref{Name: "RFC 7515 — JSON Web Signature (JWS)", URL: "https://www.rfc-editor.org/rfc/rfc7515"}
	RFC7517 = demokit.Ref{Name: "RFC 7517 — JSON Web Key (JWK)", URL: "https://www.rfc-editor.org/rfc/rfc7517"}
	RFC7519 = demokit.Ref{Name: "RFC 7519 — JSON Web Token (JWT)", URL: "https://www.rfc-editor.org/rfc/rfc7519"}
	RFC7638 = demokit.Ref{Name: "RFC 7638 — JWK Thumbprint (kid)", URL: "https://www.rfc-editor.org/rfc/rfc7638"}
)

// Token management
var (
	RFC7591 = demokit.Ref{Name: "RFC 7591 — Dynamic Client Registration", URL: "https://www.rfc-editor.org/rfc/rfc7591"}
	RFC7636 = demokit.Ref{Name: "RFC 7636 — PKCE", URL: "https://www.rfc-editor.org/rfc/rfc7636"}
	RFC7662 = demokit.Ref{Name: "RFC 7662 — Token Introspection", URL: "https://www.rfc-editor.org/rfc/rfc7662"}
	RFC8414 = demokit.Ref{Name: "RFC 8414 — AS Metadata Discovery", URL: "https://www.rfc-editor.org/rfc/rfc8414"}
)

// Rich Authorization Requests
var (
	RFC9396 = demokit.Ref{Name: "RFC 9396 — Rich Authorization Requests", URL: "https://www.rfc-editor.org/rfc/rfc9396"}
)

// Security
var (
	RFC9728 = demokit.Ref{Name: "RFC 9728 — Protected Resource Metadata", URL: "https://www.rfc-editor.org/rfc/rfc9728"}

	CVE_2015_9235 = demokit.Ref{Name: "CVE-2015-9235 — JWT Algorithm Confusion", URL: "https://nvd.nist.gov/vuln/detail/CVE-2015-9235"}
)
