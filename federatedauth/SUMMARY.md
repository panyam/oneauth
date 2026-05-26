# federatedauth/ — OAuth/SAML Callback Orchestration

Provider-mediated authentication orchestration. Owns the HTTP handlers that
OAuth and SAML callbacks dispatch through, plus the channel-aware user
creation logic that turns provider userInfo into an `accounts.User`.

## Contents
- **callback.go** — `OAuthBridge` (wraps `*httpauth.OneAuth` + `AuthUserStore`), `SaveUserAndRedirect`, `HandleLinkOAuthCallback`, `StartLinkOAuth`, `GetLinkingUserID`, `AuthUserStore` (composite interface)
- **ensure_user.go** — `EnsureAuthUserConfig`, `EnsureAuthUserFunc`, `NewEnsureAuthUserFunc`, `handleExistingUser`, `handleNewUser`
- **util.go** — internal helpers

## Typical wiring

```go
bridge := federatedauth.NewOAuthBridge(oneauth, authUserStore)
oneauth.AddAuth("/google", oa2.NewGoogleOAuth2(
    clientID, clientSecret, callbackURL,
    bridge.SaveUserAndRedirect,  // accounts.HandleUserFunc shape
).Handler())
```

## Who uses this
- Host applications wiring OAuth/SAML providers.
- Consumes [`accounts/`](../accounts/SUMMARY.md) (User/Identity/Channel + stores) and [`httpauth/`](../httpauth/SUMMARY.md) (session/cookies/JWT).

## What moved here
- From `httpauth/mux.go`: `SaveUserAndRedirect`, `HandleLinkOAuthCallback`, `LinkOAuthConfig` (now folded into `AuthUserStore`), `StartLinkOAuth`, `GetLinkingUserID`, `AuthUserStore`
- From `localauth/helpers.go`: `EnsureAuthUserConfig`, `NewEnsureAuthUserFunc`, `handleExistingUser`, `handleNewUser` (provider-driven, not username/password)
