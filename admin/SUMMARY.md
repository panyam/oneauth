# admin/ — Admin Auth & App Registration

Admin authentication, app registration API, and resource token minting for the federated auth flow.

## Contents
- **auth.go** — `AdminAuth` interface, `NoAuth`, `APIKeyAuth` (X-Admin-Key header)
- **registrar.go** — `AppRegistrar` HTTP handler (register/list/delete/rotate apps), `AppRegistration`, `SaveRegistration`
- **appstore.go** — `AppRegistrationStore` interface + `InMemoryAppStore` (issue 165). `ErrAppNotFound`. Persistent backends in `stores/fs/` and `stores/gorm/` (issues 166, 167).
- **dcr.go** — `DCRHandler` for RFC 7591 Dynamic Client Registration at `POST /apps/dcr`. Now issues RFC 7592 §3 management credentials (`registration_access_token`, `registration_client_uri`) on every successful registration.
- **client_management.go** — `ClientRegistrationManager` interface + `ErrUnauthorized` (issue 168). Transport-agnostic core for the RFC 7592 management surface — handlers in `dcr_management.go` are thin wrappers. Blueprint for the wider admin/ refactor tracked under issue 172.
- **dcr_management.go** — `DCRManagementHandler` for RFC 7592 reads at `GET /apps/dcr/{client_id}` (issue 168). PUT / DELETE arrive in 169 / 170.
- **mint.go** — `MintResourceToken()`, `MintResourceTokenWithKey()`, `AppQuota`

## Dependencies
`keys/` for `KeyStorage`, `KeyRecord`, `KidStore`. `utils/` for crypto.
