# tests/keycloak — Keycloak interop gotchas

Run with `make testkcl` (auto-starts Docker). See [README.md](README.md).

- **Port collisions.** Default `KC_PORT=8180`, `RAR_PORT=8181`. `mcpkit-keycloak` often holds 8180; use `make upkcl KC_PORT=8281 && make testkcl KC_PORT=8281`, and add `RAR_PORT=8381` when 8181 is taken (moves the RAR server too, issue 458).
- **`make testkcl` reuses a running container.** A realm edited in `realm.json` doesn't reach a container started earlier. `make downkcl` first whenever the realm changed, or tests fail in ways that look like code bugs.
- **`make testkcl` reuses whatever answers on `RAR_PORT`.** A RAR server left running from another worktree or build gets tested instead. Check `lsof -iTCP:8181 -sTCP:LISTEN` and stop it, or use `RAR_PORT=8381`.
- **The RAR test issuer** is `cmd/oneauth-server/deploy-examples/rar-test.yaml`, started inside `make testkcl`. `cmd/rar-test-issuer/` is retired.
- **The test realm has no built-in client scopes.** `realm.json` lists `clientScopes` explicitly, replacing Keycloak's defaults. It defines `basic`, `email` and `profile` itself, each with only the mappers a test needs (issue 542). `sub` comes from `basic`; a new client needs `basic` in `defaultClientScopes` or its tokens carry no `sub`. Keycloak 26.x refuses to introspect unless the caller is in the token's `aud`, hence the `self-audience` mapper on `test-confidential`.
- **DPoP is a Keycloak preview feature.** `upkcl` / `testkcl` pass `--features=dpop`. GitHub Actions `services:` can't pass container arguments, so `keycloak-interop.yml` runs `make testkcl`, which starts the `keycloak` service in `docker-compose.yml`.
- **Keycloak answers `/authorize` errors with JSON when `Accept` lists `application/json`**, which headless openers send. Its message goes in `error` (`{"error":"Invalid parameter: redirect_uri"}`), so `AuthorizeError.Code` is a sentence, not an RFC 6749 code.
- **A `LoginWithBrowser` test against Keycloak** needs an opener that fills in Keycloak's login form: `testutil.KeycloakPasswordLogin`. `FollowRedirects` and `ApproveConsent` stop at that form on purpose.
- **The CLI tests build `cmd/oneauth` through the repo's `go.work`**, even under `GOWORK=off`, so the CLI compiles against this checkout's root and not the last tag (issue 410).
- **`cmd/exercise-jarm`** drives `make exercise-jarm` (issue 409) against the `test-jarm` client, which signs authorization responses with PS256. Keycloak's JARM JWT carries `iss` twice.
- **RP-initiated logout needs `id_token_hint`.** Without it Keycloak shows its own logout confirmation page and never redirects to `post_logout_redirect_uri`. The redirect URI must also be allowed: `test-confidential` sets `post.logout.redirect.uris` to `+`, which reuses its redirect URIs (issue 546).
- **A test needing realm config can make it through the admin API** and remove it in `t.Cleanup`, as `TestKeycloak_VerifiesOneauthPS256IDToken` does with an identity provider, a client and a federated link. `realm.json` then stays unchanged and a running container needs no `make downkcl` (issue 558).
- **CI**: the Keycloak workflow runs on PRs touching `apiauth/`, `client/`, `keys/`, `core/`, `oauth2/`, `cmd/oneauth-server/` or `tests/keycloak/`, and on pushes to main.
