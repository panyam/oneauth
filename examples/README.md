# OneAuth Examples

Progressive examples demonstrating OneAuth's authentication and authorization capabilities. Start at 01 and work your way up — each builds on concepts from the previous.

## Cast of Characters

Every example involves the same cast. To make them concrete, imagine you're building **Slack** — a messaging app with channels, bots, and third-party integrations.

### The players

| Term                     | In Slack                                                                            | What it does                                                                                                                          | In the examples                                             |
|--------------------------|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| **Auth Server (AS)**     | Slack's identity service                                                            | Manages user accounts, registers apps, issues tokens, serves public keys (JWKS). The source of truth for "who is allowed to do what." | `authServer` — token endpoint, JWKS, introspection          |
| **Resource Server (RS)** | Slack's API (channels, messages, files)                                             | Protects resources behind token validation. Checks every request: "does this token grant access to this channel?"                     | `resourceServer` — validates Bearer tokens, enforces scopes |
| **App (Client)**         | A Slack bot or third-party integration (e.g., the GitHub bot that posts PR updates) | Registers with the AS, gets credentials, then requests tokens to act on its own behalf or on behalf of users.                         | The code making HTTP calls                                  |
| **User**                 | A person using Slack (sending messages, joining channels)                           | The human the token represents. Some flows have no user (bot-to-bot); others carry a specific user's identity.                        | `alice`, `bob` — subjects in tokens                         |
| **Developer**            | You, building the GitHub bot                                                        | Writes the App code, registers it with the AS, decides what scopes to request.                                                        | You, running these examples                                 |
| **Admin**                | Slack workspace admin                                                               | Configures the AS: which apps are allowed, what scopes exist, key rotation policies.                                                  | Sets up `AppRegistrar`, `APIKeyAuth`                        |

### How they connect

```
Developer builds the App (GitHub bot)
         │
         ▼
   ┌──────────┐     registers      ┌───────────┐
   │   App    │ ──────────────────▶│  Auth     │
   │ (GitHub  │     gets tokens    │  Server   │
   │   bot)   │ ◀──────────────────│  (AS)     │
   └────┬─────┘                    └──────┬────┘
        │                                 │
        │  Bearer token                   │  serves JWKS
        ▼                                 ▼
   ┌──────────┐    validates token  ┌──────────┐
   │ Resource │  ◀─ ─ ─ ─ ─ ─ ─ ─   │  JWKS    │
   │  Server  │    (using pub key)  │ endpoint │
   │ (Slack   │                     └──────────┘
   │   API)   │
   └──────────┘
```

### How does an App get registered?

Before an App can get tokens, it must register with the Auth Server and receive credentials (`client_id` + `client_secret`). But who is allowed to register?

| Method | Real-world example | Who acts | Automated? |
|--------|-------------------|----------|-----------|
| **Web dashboard** | GitHub Developer Settings, Google Cloud Console | Developer logs in, fills a form | No — human reviews |
| **Admin API** | Internal tooling with `X-Admin-Key` | Admin provisions via script | Yes, gated by admin key |
| **DCR + access token** | RFC 7591 §3 | Developer's code self-registers | Yes, gated by one-time token |
| **Open DCR** | Examples in this repo (`NewNoAuth()`) | Anyone | Yes, **ungated — not for production** |

**In these examples**, registration is open (`NewNoAuth()`) for simplicity. In production, always gate registration with authentication — see `admin.NewAPIKeyAuth()` or protect the endpoint at the network level.

**Important:** The `client_secret` is a backend credential. It lives in your server, not in a browser or mobile app. Frontend apps use PKCE (public clients) instead of secrets.

### When is a user involved?

| Flow | Slack equivalent | User involved? | Who authenticates? |
|------|-----------------|---------------|-------------------|
| Client Credentials (Example 01) | Bot posts to #general using its own identity | No — the bot acts as itself | The app (bot) authenticates with client_id + secret |
| Resource Token (Example 02-03) | Bot posts to #general *as Alice* (on her behalf) | Yes — token carries Alice's user ID | The app mints a token for Alice |
| Auth Code + PKCE (future) | Alice clicks "Sign in with Slack" on a third-party site | Yes — Alice logs in via browser | The user authenticates directly |

## Examples

| #                                     | Example                       | Type   | Infra               | Keycloak | What you'll learn                                                      |
|---------------------------------------|-------------------------------|--------|---------------------|----------|------------------------------------------------------------------------|
| [01](01-client-credentials/README.md)          | Client Credentials            | Non-UI | None                | —        | Get your first token via the HTTP token endpoint                       |
| [02](02-resource-token-hs256/README.md)        | Resource Token (HS256)        | Non-UI | None                | —        | Federated auth: app registers, mints tokens, resource server validates |
| [03](03-resource-token-rs256-jwks/README.md)   | Resource Token (RS256 + JWKS) | Non-UI | None                | —        | Asymmetric signing with automatic JWKS key discovery                   |
| [04](04-discovery/README.md)          | AS Metadata Discovery         | Non-UI | KC optional         | Optional | Auto-discover endpoints — no hardcoded URLs                            |
| [05](05-introspection/README.md)               | Token Introspection           | Non-UI | KC optional         | Optional | Remote token validation via RFC 7662                                   |
| [06](06-dynamic-client-registration/README.md) | Dynamic Client Registration   | Non-UI | KC optional         | Optional | Self-service client onboarding via RFC 7591                            |
| [07](07-client-sdk/README.md)                  | Client SDK                    | Non-UI | KC optional         | Optional | Production patterns: caching, auto-refresh, scope step-up              |
| [08](08-rich-authorization-requests/README.md) | Rich Authorization Requests   | Non-UI | RAR issuer optional | —        | Fine-grained authorization beyond scopes (RFC 9396)                    |
| [09](09-key-rotation/README.md)                | Key Rotation                  | Non-UI | None                | —        | Rotate secrets with grace periods — zero downtime                      |
| [10](10-security/README.md)                    | Security                      | Non-UI | None                | —        | Attack prevention: algorithm confusion, cross-app forgery              |

**Keycloak column:** Examples marked "Optional" have an extra step that runs against Keycloak if it's available, showing the same code working against a real-world IdP. Start KC with `cd examples && make upkcl`. All examples work without KC — the KC steps skip gracefully.

## Run examples

```bash
# Interactive step-through
cd examples/01-client-credentials && make run

# Non-interactive (full output)
cd examples/01-client-credentials && make demo

# Regenerate all READMEs from code
cd examples && make readmes
```

## How the examples work

Every example is a standalone `main.go` you run with `go run`. No external services needed — they spin up in-memory stores and `httptest` servers, make real HTTP calls, and print step-by-step output.

In interactive mode (`make run`), the example pauses between steps so you can follow along with the README's sequence diagram. In non-interactive mode (`make demo`), it runs straight through.

READMEs are generated from the code (`make readme` in each directory). The sequence diagrams, step descriptions, and reference links are all defined in the Go source — single source of truth.
