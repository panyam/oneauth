# admin/ — Admin Auth & App Registration

Admin authentication, app registration API, and resource token minting for the federated auth flow.

## Contents
- **auth.go** — `AdminAuth` interface, `NoAuth`, `APIKeyAuth` (X-Admin-Key header)
- **registrar.go** — `AppRegistrar` HTTP handler (register/list/delete/rotate apps), `AppRegistration`, `SaveRegistration`
- **appstore.go** — `AppRegistrationStore` interface + `InMemoryAppStore` (issue 165). `ErrAppNotFound`. Persistent backends in `stores/fs/` and `stores/gorm/` (issues 166, 167).
- **dcr.go** — `DCRHandler` for RFC 7591 Dynamic Client Registration at `POST /apps/dcr`. Now issues RFC 7592 §3 management credentials (`registration_access_token`, `registration_client_uri`) on every successful registration.
- **client_management.go** — `ClientRegistrationManager` interface + `ErrUnauthorized` + `ErrInvalidClientMetadata`. Transport-agnostic core for the RFC 7592 management surface (self-service, authed by registration_access_token). Methods follow the `(ctx context.Context, *XRequest) → (*XResponse, error)` convention.
- **client_admin.go** — `ClientRegistrar` interface (issue 172) covering admin operations: `Register` (RFC 7591), `RegisterLegacy` (proprietary `/apps/register`), `ListClients`, `GetClient`, `DeleteClient`, `RotateSecret`. Sentinels: `ErrInvalidPublicKey`, `ErrPublicKeyRequired`. Distinct from `ClientRegistrationManager` — admin scope vs self-service scope, different security models. Both implemented by `AppRegistrar`. `DCRHandler.ServeHTTP` and the legacy `handleX` methods are now thin HTTP wrappers around this interface. Blueprint for the apiauth port under issue 175.
- **dcr_management.go** — `DCRManagementHandler` HTTP wrapper for the full RFC 7592 verb trio at `/apps/dcr/{client_id}`: `GET` (issue 168), `PUT` (issue 169), `DELETE` (issue 170). 405 on any other verb with `Allow: GET, PUT, DELETE`.
- **mint.go** — `MintResourceToken(userID, appClientID, signingKey, customClaims, scopes, authzDetails)`. Single entry point: signing alg auto-selected from the key's Go type (`[]byte` → HS256, `*rsa.PrivateKey` → RS256, `*ecdsa.PrivateKey` → ES256). `customClaims map[string]any` rides alongside the standard claims; collisions with the standard set (`sub`, `iss`, `aud`, `exp`, `iat`, `type`, `scopes`, `jti`, `client_id`, `authorization_details`) are logged and dropped.

## Dependencies
`keys/` for `KeyStorage`, `KeyRecord`, `KidStore`. `utils/` for crypto.
