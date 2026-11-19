# client — SDK gotchas

- **`AuthClient` defaults to `/auth/cli/token`** for `Login` and refresh when it has no AS metadata. Against an `apiauth` fixture on `/api/token`, pass `client.WithASMetadata(&client.ASMetadata{TokenEndpoint: server.URL + "/api/token"})`, or the JSON decode fails confusingly.
- **`err.Error()` from `LoginWithBrowser` contains the whole authorize URL** when the opener fails (`BrowserOpenError`), so `Contains(err.Error(), "redirect_uri")` passes for any opener failure. Assert on typed fields via `errors.As`.
- **A DPoP proof is single-use.** Any retry (the refresh-then-retry in `client.go`) mints a fresh proof. Reuse looks fine against a single node with an in-memory `JTIStore`.
- **The SDK checks an ID token only when asked** (`BrowserLoginRequest.VerifyIDToken`); otherwise it keeps it unverified on `ServerCredential.IDToken`, since many servers accept `openid` and return none. Verification needs the issuer and `jwks_uri`; against Keycloak with explicit endpoints pass `WithASMetadata` (discovery from the server URL loses the realm path).
- **The loopback listener binds `localhost`.** `LoginWithBrowser` without a `Listener` sends `http://localhost:<port>/callback`, and `/authorize` relaxes only the port, so DCR registrations must say `localhost`, not `127.0.0.1`.
