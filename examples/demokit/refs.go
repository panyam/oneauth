package demokit

// Pre-defined references for common standards. Use these in Step.Ref() calls
// to avoid typing URLs repeatedly and to ensure consistent naming.
//
// Usage:
//
//	demo.Step("Get a token").
//	    Ref(demokit.RFC6749_ClientCredentials).
//	    Ref(demokit.RFC7519).
//	    Run(func() { ... })

// OAuth 2.0
var (
	RFC6749                    = Ref{"RFC 6749 — OAuth 2.0", "https://www.rfc-editor.org/rfc/rfc6749"}
	RFC6749_ClientCredentials  = Ref{"RFC 6749 §4.4 — Client Credentials Grant", "https://www.rfc-editor.org/rfc/rfc6749#section-4.4"}
	RFC6749_AuthorizationCode  = Ref{"RFC 6749 §4.1 — Authorization Code Grant", "https://www.rfc-editor.org/rfc/rfc6749#section-4.1"}
	RFC6750                    = Ref{"RFC 6750 — Bearer Token Usage", "https://www.rfc-editor.org/rfc/rfc6750"}
)

// JWT / JWS / JWK
var (
	RFC7515 = Ref{"RFC 7515 — JSON Web Signature (JWS)", "https://www.rfc-editor.org/rfc/rfc7515"}
	RFC7517 = Ref{"RFC 7517 — JSON Web Key (JWK)", "https://www.rfc-editor.org/rfc/rfc7517"}
	RFC7519 = Ref{"RFC 7519 — JSON Web Token (JWT)", "https://www.rfc-editor.org/rfc/rfc7519"}
	RFC7638 = Ref{"RFC 7638 — JWK Thumbprint (kid)", "https://www.rfc-editor.org/rfc/rfc7638"}
)

// Token management
var (
	RFC7591 = Ref{"RFC 7591 — Dynamic Client Registration", "https://www.rfc-editor.org/rfc/rfc7591"}
	RFC7636 = Ref{"RFC 7636 — PKCE", "https://www.rfc-editor.org/rfc/rfc7636"}
	RFC7662 = Ref{"RFC 7662 — Token Introspection", "https://www.rfc-editor.org/rfc/rfc7662"}
	RFC8414 = Ref{"RFC 8414 — AS Metadata Discovery", "https://www.rfc-editor.org/rfc/rfc8414"}
)

// Rich Authorization Requests
var (
	RFC9396 = Ref{"RFC 9396 — Rich Authorization Requests", "https://www.rfc-editor.org/rfc/rfc9396"}
)

// Security
var (
	RFC9728 = Ref{"RFC 9728 — Protected Resource Metadata", "https://www.rfc-editor.org/rfc/rfc9728"}

	CVE_2015_9235 = Ref{"CVE-2015-9235 — JWT Algorithm Confusion", "https://nvd.nist.gov/vuln/detail/CVE-2015-9235"}
)
