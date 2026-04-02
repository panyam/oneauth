# oauth2/ — OAuth2 Provider Implementations

OAuth2 authorization code flow for Google and GitHub, with PKCE (RFC 7636) support.

## Contents
- **base.go** — `BaseOAuth2` struct, shared redirect/callback logic, `DisablePKCE`, `SecureCookies`
- **google.go** — `GoogleOAuth2` (Google OAuth2 provider)
- **github.go** — `GithubOAuth2` (GitHub OAuth2 provider)
- **utils.go** — `OauthRedirector`, `OauthRedirectorWithPKCE`, state cookie generation
- **pkce.go** — `GenerateCodeVerifier`, `ComputeCodeChallenge`, PKCE cookie helpers

## PKCE (default: enabled)
All flows include `code_challenge` (S256) in the authorization URL and send `code_verifier` during token exchange. Set `DisablePKCE=true` to opt out (logs warning).

## Note: Separate Go Module
This package is a separate Go module (`github.com/panyam/oneauth/oauth2`) with its own `go.mod`. It depends on `golang.org/x/oauth2` but NOT on the oneauth core module.

## Dependencies
`golang.org/x/oauth2`, `golang.org/x/oauth2/google`, `golang.org/x/oauth2/github`
