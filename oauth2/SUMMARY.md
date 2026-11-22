# oauth2/ — OAuth2 Provider Implementations

OAuth2 authorization code flow for Google and GitHub, with PKCE (RFC 7636) support. `oidc/` adds a provider for any OpenID Connect issuer.

## Contents
- **base.go** — `BaseOAuth2` struct, shared redirect/callback logic, `DisablePKCE` (every cookie is Secure + HttpOnly), `SetScopes` / `Scopes`, and `AllowedExtraScopes` (a login link adds scopes with `?scope=`, limited to the list; issue #467)
- **google.go** — `GoogleOAuth2` (Google OAuth2 provider)
- **github.go** — `GithubOAuth2` (GitHub OAuth2 provider). `SetEnterpriseURL` points it at a GitHub Enterprise Server or GHE.com host (issue 511)
- **github_hosts.go** — `GitHubHostsFor(api)` maps a GitHub REST API root to its web host, OAuth endpoint and `/user` URL for github.com, GHES and GHE.com; other roots serve everything on themselves. `SetEnterpriseURL` uses it, and agni and goapplib can too (issue 554)

## Testing against a fake provider
`SetOAuthEndpoint` sets the authorize and token URLs, `UserInfoURL` sets the profile URL, and `SetHTTPClient` sets the client. A callback whose userinfo answers anything but 200 fails the sign-in. Neither provider logs a token or puts one in a URL (issue 510).
- **utils.go** — `OauthRedirector`, `OauthRedirectorWithPKCE`, state cookie generation. `RedirectWithPKCE` (with extra authorize parameters) and `VerifyState` let a provider in another package set and check the same cookies. The GitHub and Google callbacks check state through `VerifyState` too, and every state failure answers 400 `invalid oauth state` (issue 546).
- **oidc/** — `oidc.New(ctx, Config)` signs in through any OpenID Connect provider by issuer URL (Entra ID, Okta, Google Workspace, Keycloak). Discovery runs once in `New`, and the JWKS is fetched on first use and on an unknown `kid`. The browser flow adds a `nonce` cookie beside state and PKCE, and `HandleUser` receives the claims of an ID token checked by `client.VerifyIDToken`. `DeviceAuth` / `DeviceAccessToken` sign in from a CLI and send the client secret at the device endpoint, which `x/oauth2` leaves out. `AllowList` admits people by verified email domain, group, `sub` or Google's `hd` claim, and allows nobody when empty. `Decide` names the matched rule and flags Entra's groups overage (`_claim_names`); `Resolve` fetches the groups through a `GroupsSource` such as `EntraGroups`, which calls Graph `getMemberObjects` (issue 555). `LogoutURL` builds the RP-initiated logout redirect from the discovery document's `end_session_endpoint`, with `id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state` (issue 546). `example/` runs against the docker-compose Keycloak. This subpackage imports the root module; the base package doesn't (issue 542).
- **pkce.go** — `GenerateCodeVerifier`, `ComputeCodeChallenge`, PKCE cookie helpers

## PKCE (default: enabled)
All flows include `code_challenge` (S256) in the authorization URL and send `code_verifier` during token exchange. Set `DisablePKCE=true` to opt out (logs warning).

## Note: Separate Go Module
This package is a separate Go module (`github.com/panyam/oneauth/oauth2`) with its own `go.mod`. The base package imports only `golang.org/x/oauth2`. The `oidc` subpackage imports the root module for discovery and ID token checks, so `go.mod` requires it, but GitHub/Google users compile none of it.

## Dependencies
`golang.org/x/oauth2`, `golang.org/x/oauth2/google`, `golang.org/x/oauth2/github`
