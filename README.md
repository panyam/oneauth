# OneAuth

An **embeddable Go authentication library** for apps and resource servers. Local auth (signup, login, email verification, password reset), OAuth2 / OIDC client flows, multi-tenant JWT issuance and validation, federated app registration, and a small reference server you can deploy as-is or treat as a worked example.

OneAuth is **not** trying to be a full identity provider — it interoperates with real IdPs (Keycloak interop is in CI) and focuses on making Go services easy to secure with standards-compliant pieces. See [docs/ROADMAP.md](docs/ROADMAP.md) for vision and what's deliberately out of scope.

## Why OneAuth?

- **Library, not a sidecar.** Embed in your Go service. No extra process, no auth-server-as-product to operate.
- **Composed interfaces, no god objects.** Every transport-agnostic surface follows `Method(ctx, *XRequest) (*XResponse, error)` — `TokenIssuer` / `TokenValidator` / `TokenIntrospector` / `TokenRevoker` / `ClientAuthenticator` / `ClientRegistrationManager` / `ClientRegistrar`. HTTP handlers are thin wrappers.
- **Storage-agnostic.** Three backends ship for every store interface — file (dev), GORM (Postgres / MySQL / SQLite), GAE/Datastore. Bring your own by implementing the interfaces.
- **Lightweight core.** Top-level module pulls ~6 deps (jwt, scs, x/crypto, x/oauth2, …). Heavy backends (GORM, GAE, SAML, gRPC) are separate Go sub-modules so consumers only download what they use. See [docs/MIGRATION.md](docs/MIGRATION.md) for the sub-module layout.
- **Real interop.** Keycloak conformance suite runs against a live container in `tests/keycloak/`. Gap analyses vs Auth0 and Authlete live in [docs/gaps/](docs/gaps/).

## Standards

| Endpoint / Feature | RFC |
|---|---|
| Token endpoint — password, refresh, client_credentials, jwt-bearer, token-exchange | RFC 6749, 7523, 8693 |
| Token Introspection (`/oauth/introspect`) | RFC 7662 |
| Token Revocation (`/oauth/revoke`) | RFC 7009 |
| Authorization Server Metadata + OIDC Discovery | RFC 8414 |
| JWKS (`/.well-known/jwks.json`) | RFC 7517, 7638 |
| Protected Resource Metadata | RFC 9728 |
| Dynamic Client Registration | RFC 7591 |
| DCR Management (GET / PUT / DELETE on `/apps/dcr/{client_id}`) | RFC 7592 |
| Rich Authorization Requests (`authorization_details`) | RFC 9396 |
| `iss` on authorize redirect | RFC 9207 |
| PKCE on OAuth2 social login + headless CLI login | RFC 7636, 8252 |
| Private Key JWT client auth (`private_key_jwt`) | RFC 7521, 7523 |

A full Authlete-superset gap analysis lives at [docs/gaps/AUTHLETE_GAP_ANALYSIS.md](docs/gaps/AUTHLETE_GAP_ANALYSIS.md).

## Install

```bash
go get github.com/panyam/oneauth@latest
```

Sub-modules (only pull what you need):

```bash
go get github.com/panyam/oneauth/stores/gorm@latest
go get github.com/panyam/oneauth/stores/gae@latest
go get github.com/panyam/oneauth/grpc@latest
go get github.com/panyam/oneauth/saml@latest
```

## Where to start

| You want to… | Go here |
|---|---|
| Wire up local signup/login in a Go service | [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) |
| Walk through OAuth concepts hands-on, one RFC at a time | [examples/](examples/) — 10 progressive runnable examples |
| Protect API endpoints with JWT (multi-tenant, JWKS-aware) | [docs/API_AUTH.md](docs/API_AUTH.md) |
| Run an authorization server today | [`cmd/oneauth-server/`](cmd/oneauth-server/) — config-driven, deployable to GAE / Docker / K8s |
| See the whole federated flow (auth + apps + resource servers) locally | [`demo/`](demo/) — 6-service Docker Compose |
| Use the client SDK from a CLI tool | [docs/CLIENT_SDK.md](docs/CLIENT_SDK.md) |
| Understand the design decisions and rationale | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |

## Architecture

Three-layer data model for end-user accounts. Lives in `accounts/`:

```
User: alice@example.com
├── Identity: alice@example.com (verified)
├── Channel: local    (password hash)
├── Channel: google   (OAuth tokens)
└── Channel: github   (OAuth tokens)
```

- **User** — your application account.
- **Identity** — a contact handle (email, phone) with verification status, shared across channels.
- **Channel** — one authentication mechanism (local, google, github, …) carrying provider-specific credentials.

Verifying an identity through any channel verifies it everywhere. New channels can be linked onto an existing user by matching identity.

For the token lifecycle, federated-auth flow, and the rest of the data model, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Package map

Every package has a `DESIGN.md` (rich) and `SUMMARY.md` (LLM-friendly index). The top-level tour is [MAP.md](MAP.md).

| Package | Role |
|---|---|
| [`accounts/`](accounts/DESIGN.md) | User / Identity / Channel model + store interfaces |
| [`core/`](core/DESIGN.md) | Tokens, scopes, RFC 9396 authorization_details, rate-limit/blacklist primitives |
| [`keys/`](keys/DESIGN.md) | Signing-key storage, kid lookup, encryption-at-rest, JWKS, rotation grace |
| [`localauth/`](localauth/DESIGN.md) | Local signup, login, verification, password reset, credential linking |
| [`federatedauth/`](federatedauth/DESIGN.md) | OAuth/SAML callback orchestration, channel linking onto existing users |
| [`httpauth/`](httpauth/DESIGN.md) | Session/JWT-aware login mux, CSRF, body-limit, security-header middleware |
| [`apiauth/`](apiauth/DESIGN.md) | Token issuance, JWT middleware, introspection, revocation, discovery |
| [`admin/`](admin/DESIGN.md) | App registration (DCR + RFC 7592 + admin CRUD), resource-token minting |
| [`oauth2/`](oauth2/DESIGN.md) | Google / GitHub social-login providers with PKCE |
| [`saml/`](saml/DESIGN.md) | SAML 2.0 SP adapter (POC) |
| [`client/`](client/DESIGN.md) | Client SDK — discovery, browser/CLI/M2M login, token cache, auto-refresh |
| [`grpc/`](grpc/DESIGN.md) | Auth context propagation across HTTP↔gRPC boundary |
| [`stores/fs`](stores/fs/DESIGN.md) · [`stores/gorm`](stores/gorm/DESIGN.md) · [`stores/gae`](stores/gae/DESIGN.md) | Backend implementations of every store interface |
| [`testutil/`](testutil/DESIGN.md) | In-process RS256 AS + JWKS + DCR fixture for downstream tests |

## Documentation

| Document | What it covers |
|---|---|
| [GETTING_STARTED](docs/GETTING_STARTED.md) | Install, store setup, first auth flow |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Design decisions, data model, token lifecycle, federated auth |
| [API_AUTH](docs/API_AUTH.md) | JWT middleware, custom claims, multi-tenant validation |
| [BROWSER_AUTH](docs/BROWSER_AUTH.md) | OAuth flows, channel linking, session management |
| [FEDERATED_AUTH](docs/FEDERATED_AUTH.md) | App registration, MintResourceToken, AdminAuth |
| [JWT_SIGNING](docs/JWT_SIGNING.md) | HS256 / RS256 / ES256 keys, JWKS, rotation |
| [CLIENT_SDK](docs/CLIENT_SDK.md) | CLI / programmatic clients, browser-login, refresh |
| [STORES](docs/STORES.md) | Store interfaces and implementations |
| [GRPC](docs/GRPC.md) | gRPC context utilities + interceptors |
| [AUTH_FLOWS](docs/AUTH_FLOWS.md) | Login/signup decision trees, edge cases |
| [TESTING](docs/TESTING.md) | Test patterns, security references |
| [MIGRATION](docs/MIGRATION.md) | Sub-module layout, consumer migration guide |
| [CONFORMANCE](docs/CONFORMANCE.md) | Conformance / load / adversarial test strategy |
| [RELEASE_NOTES](docs/RELEASE_NOTES.md) | Version history |
| [godoc](https://pkg.go.dev/github.com/panyam/oneauth) | Generated API reference |

## Build & test

```bash
make test          # Unit tests
make e2e           # In-process e2e (~2s)
make testkcl       # Keycloak interop + RAR conformance (Docker)
make testall       # 9-stage matrix + report
```

Reference deployment lives in [`cmd/oneauth-server/`](cmd/oneauth-server/). The 6-service federated demo (auth + 2 apps + 2 resource servers + Postgres) lives in [`demo/`](demo/) — see [docs/DEMOS.md](docs/DEMOS.md).

## License

See [LICENSE](LICENSE).
