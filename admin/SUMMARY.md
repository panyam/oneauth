# admin/ — Admin Auth & App Registration

Admin authentication, app registration API, and resource token minting for the federated auth flow.

## Contents
- **auth.go** — `AdminAuth` interface, `NoAuth`, `APIKeyAuth` (X-Admin-Key header)
- **registrar.go** — `AppRegistrar` HTTP handler (register/list/delete/rotate apps), `AppRegistration`
- **dcr.go** — `DCRHandler` for RFC 7591 Dynamic Client Registration at `POST /apps/dcr`
- **mint.go** — `MintResourceToken()`, `MintResourceTokenWithKey()`, `AppQuota`

## Dependencies
`keys/` for `KeyStorage`, `KeyRecord`, `KidStore`. `utils/` for crypto.
