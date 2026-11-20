# oauth2/ — OAuth2 Provider Implementations

OAuth2 authorization code flow for Google and GitHub, with PKCE (RFC 7636) support.

## Contents
- **base.go** — `BaseOAuth2` struct, shared redirect/callback logic, `DisablePKCE` (every cookie is Secure + HttpOnly), `SetScopes` / `Scopes`, and `AllowedExtraScopes` (a login link adds scopes with `?scope=`, limited to the list; issue #467)
- **google.go** — `GoogleOAuth2` (Google OAuth2 provider)
- **github.go** — `GithubOAuth2` (GitHub OAuth2 provider). `SetEnterpriseURL` points it at a GitHub Enterprise Server or GHE.com host (issue 511)

## Testing against a fake provider
`SetOAuthEndpoint` sets the authorize and token URLs, `UserInfoURL` sets the profile URL, and `SetHTTPClient` sets the client. A callback whose userinfo answers anything but 200 fails the sign-in. Neither provider logs a token or puts one in a URL (issue 510).
- **utils.go** — `OauthRedirector`, `OauthRedirectorWithPKCE`, state cookie generation
- **pkce.go** — `GenerateCodeVerifier`, `ComputeCodeChallenge`, PKCE cookie helpers

## PKCE (default: enabled)
All flows include `code_challenge` (S256) in the authorization URL and send `code_verifier` during token exchange. Set `DisablePKCE=true` to opt out (logs warning).

## Note: Separate Go Module
This package is a separate Go module (`github.com/panyam/oneauth/oauth2`) with its own `go.mod`. It depends on `golang.org/x/oauth2` but NOT on the oneauth core module.

## Dependencies
`golang.org/x/oauth2`, `golang.org/x/oauth2/google`, `golang.org/x/oauth2/github`
