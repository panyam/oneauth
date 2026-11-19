# tests/keycloak — Keycloak interop gotchas

Run with `make testkcl` (auto-starts Docker). See [README.md](README.md).

- **Port collisions.** Default `KC_PORT=8180`, `RAR_PORT=8181`. `mcpkit-keycloak` often holds 8180; use `make upkcl KC_PORT=8281 && make testkcl KC_PORT=8281`, and add `RAR_PORT=8381` when 8181 is taken (moves the RAR server too, issue 458).
- **`make testkcl` reuses a running container.** A realm edited in `realm.json` doesn't reach a container started earlier. `make downkcl` first whenever the realm changed, or tests fail in ways that look like code bugs.
- **`make testkcl` reuses whatever answers on `RAR_PORT`.** A RAR server left running from another worktree or build gets tested instead. Check `lsof -iTCP:8181 -sTCP:LISTEN` and stop it, or use `RAR_PORT=8381`.
- **The RAR test issuer** is `cmd/oneauth-server/deploy-examples/rar-test.yaml`, started inside `make testkcl`. `cmd/rar-test-issuer/` is retired.
- **The test realm has no built-in client scopes.** `realm.json` lists `clientScopes` explicitly, replacing Keycloak's defaults, so `openid` / `email` / `profile` don't exist. `sub` comes from the `basic` scope the realm defines; a new client needs `basic` in `defaultClientScopes` or its tokens carry no `sub`. Keycloak 26.x refuses to introspect unless the caller is in the token's `aud`, hence the `self-audience` mapper on `test-confidential`.
- **DPoP is a Keycloak preview feature.** `upkcl` / `testkcl` pass `--features=dpop`. GitHub Actions `services:` can't pass container arguments, so `keycloak-interop.yml` runs `make testkcl` (an explicit `docker run`).
- **Keycloak answers `/authorize` errors with JSON when `Accept` lists `application/json`**, which headless openers send. Its message goes in `error` (`{"error":"Invalid parameter: redirect_uri"}`), so `AuthorizeError.Code` is a sentence, not an RFC 6749 code.
- **A `LoginWithBrowser` test against Keycloak** needs an opener that fills in Keycloak's login form: `keycloakPasswordLogin` in `refresh_dpop_interop_test.go`. `FollowRedirects` and `ApproveConsent` stop at that form on purpose.
- **CI**: the Keycloak workflow runs on PRs touching `apiauth/`, `client/`, `keys/`, `core/`, `cmd/oneauth-server/` or `tests/keycloak/`, and on pushes to main.
