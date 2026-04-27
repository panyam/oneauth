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

### When is a user involved?

| Flow | Slack equivalent | User involved? | Who authenticates? |
|------|-----------------|---------------|-------------------|
| Client Credentials (Example 01) | Bot posts to #general using its own identity | No — the bot acts as itself | The app (bot) authenticates with client_id + secret |
| Resource Token (Example 02-03) | Bot posts to #general *as Alice* (on her behalf) | Yes — token carries Alice's user ID | The app mints a token for Alice |
| Auth Code + PKCE (future) | Alice clicks "Sign in with Slack" on a third-party site | Yes — Alice logs in via browser | The user authenticates directly |

## Examples

| # | Example | Type | Infra | What you'll learn |
|---|---------|------|-------|-------------------|
| [01](01-client-credentials/) | Client Credentials | Non-UI | None | Get your first token via the HTTP token endpoint |
| [02](02-resource-token-hs256/) | Resource Token (HS256) | Non-UI | None | Federated auth: app registers, mints tokens, resource server validates |
| [03](03-resource-token-rs256-jwks/) | Resource Token (RS256 + JWKS) | Non-UI | None | Asymmetric signing with automatic JWKS key discovery |
| [04](04-discovery/) | AS Metadata Discovery | Non-UI | None | Auto-discover endpoints — no hardcoded URLs |
| [05](05-introspection/) | Token Introspection | Non-UI | None | Remote token validation via RFC 7662 |
| [06](06-dynamic-client-registration/) | Dynamic Client Registration | Non-UI | None | Self-service client onboarding via RFC 7591 |
| [07](07-client-sdk/) | Client SDK | Non-UI | None | Production patterns: caching, auto-refresh, scope step-up |
| [08](08-rich-authorization-requests/) | Rich Authorization Requests | Non-UI | None | Fine-grained authorization beyond scopes (RFC 9396) |
| [09](09-key-rotation/) | Key Rotation | Non-UI | None | Rotate secrets with grace periods — zero downtime |
| [10](10-security/) | Security | Non-UI | None | Attack prevention: algorithm confusion, cross-app forgery |

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
