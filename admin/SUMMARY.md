# admin/ — Admin Auth & App Registration

Admin authentication, app registration API, and resource token minting for the federated auth flow.

## Contents
- **auth.go** — `AdminAuth` interface, `NoAuth`, `APIKeyAuth` (X-Admin-Key header)
- **registrar.go** — `AppRegistrar` HTTP handler (register/list/delete/rotate apps), `AppRegistration`, `SaveRegistration`
- **appstore.go** — `AppRegistrationStore` interface + `InMemoryAppStore` (issue 165). `ErrAppNotFound`. Persistent backends in `stores/fs/` and `stores/gorm/` (issues 166, 167).
- **dcr.go** — `DCRHandler` for RFC 7591 Dynamic Client Registration at `POST /apps/dcr`. Now issues RFC 7592 §3 management credentials (`registration_access_token`, `registration_client_uri`) on every successful registration.
- **client_management.go** — `ClientRegistrationManager` interface + `ErrUnauthorized` + `ErrInvalidClientMetadata`. Transport-agnostic core for the RFC 7592 management surface; methods follow the `(ctx context.Context, *XRequest) → (*XResponse, error)` convention so future gRPC stubs drop in cleanly. Blueprint for the wider admin/ refactor tracked under issue 172 and the apiauth port under issue 175.
- **dcr_management.go** — `DCRManagementHandler` HTTP wrapper for the full RFC 7592 verb trio at `/apps/dcr/{client_id}`: `GET` (issue 168), `PUT` (issue 169), `DELETE` (issue 170). 405 on any other verb with `Allow: GET, PUT, DELETE`.
- **mint.go** — `MintResourceToken()`, `MintResourceTokenWithKey()`, `AppQuota`

## Dependencies
`keys/` for `KeyStorage`, `KeyRecord`, `KidStore`. `utils/` for crypto.
