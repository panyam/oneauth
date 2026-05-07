# admin/ — Admin Auth & App Registration

Admin authentication, app registration API, and resource token minting for the federated auth flow.

## Contents
- **auth.go** — `AdminAuth` interface, `NoAuth`, `APIKeyAuth` (X-Admin-Key header)
- **registrar.go** — `AppRegistrar` HTTP handler (register/list/delete/rotate apps), `AppRegistration`, `SaveRegistration`
- **appstore.go** — `AppRegistrationStore` interface + `InMemoryAppStore` (issue 165). `ErrAppNotFound`. Persistent backends in `stores/fs/` and `stores/gorm/` (issues 166, 167).
- **dcr.go** — `DCRHandler` for RFC 7591 Dynamic Client Registration at `POST /apps/dcr`. Now issues RFC 7592 §3 management credentials (`registration_access_token`, `registration_client_uri`) on every successful registration.
- **client_management.go** — `ClientRegistrationManager` interface + `ErrUnauthorized` + `ErrInvalidClientMetadata`. Transport-agnostic core for the RFC 7592 management surface; methods follow the `(ctx context.Context, *XRequest) → (*XResponse, error)` convention so future gRPC stubs drop in cleanly. Blueprint for the wider admin/ refactor tracked under issue 172 and the apiauth port under issue 175.
- **dcr_management.go** — `DCRManagementHandler` HTTP wrapper for `GET /apps/dcr/{client_id}` (issue 168) and `PUT /apps/dcr/{client_id}` (issue 169). DELETE arrives in 170.
- **mint.go** — `MintResourceToken()`, `MintResourceTokenWithKey()`, `AppQuota`

## Dependencies
`keys/` for `KeyStorage`, `KeyRecord`, `KidStore`. `utils/` for crypto.
