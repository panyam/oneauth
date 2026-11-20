# CLAUDE.md — OneAuth

Go authentication library: unified local/OAuth auth, multi-tenant JWT, federated resource-server auth, and outbound credentials for calling third-party APIs. See [README.md](README.md).

## Where things are

Each package has a `SUMMARY.md`. Subsystem gotchas live in a `CLAUDE.md` beside the code, which loads when a session works there:

| Package | What | Gotchas |
|---|---|---|
| `core/` | Foundation types, store interfaces, scopes, RFC 9396 `AuthorizationDetail` | |
| `keys/` | Key storage, JWKS, `EncryptedKeyStorage`, `Sealer`, KidStore | [keys/CLAUDE.md](keys/CLAUDE.md) |
| `admin/` | AdminAuth, AppRegistrar, DCR (RFC 7591), MintResourceToken | |
| `apiauth/` | Token endpoint, authorize, DPoP, OIDC, introspection, revocation; standards table | [apiauth/CLAUDE.md](apiauth/CLAUDE.md) |
| `localauth/` / `httpauth/` | Signup/login/reset; middleware, CSRF, sessions | [localauth](localauth/CLAUDE.md), [httpauth](httpauth/CLAUDE.md) |
| `client/` | SDK (`AuthClient`, browser login, discovery) | [client/CLAUDE.md](client/CLAUDE.md) |
| `outbound/` | Token sources for third-party APIs (GitHub App, stored user tokens, static secrets) | [outbound/CLAUDE.md](outbound/CLAUDE.md) |
| `stores/` | FS, GORM, GAE backends | [stores/CLAUDE.md](stores/CLAUDE.md) |
| `*test/` | Shared contract suites; every backend runs `RunAll(t, factory)` | |
| `sshkeys/` | Ed25519 SSH keypairs (own go.mod) | |
| `cmd/oneauth-server/` | Config-driven reference server (#194) | [cmd/oneauth-server/CLAUDE.md](cmd/oneauth-server/CLAUDE.md) |
| `cmd/oneauth/` | Cobra client CLI (`oneauth token ...`) | |
| `tests/keycloak/`, `tests/oidf-conformance/` | Keycloak interop, OIDF FAPI 2.0 harness | [keycloak](tests/keycloak/CLAUDE.md), [oidf](tests/oidf-conformance/CLAUDE.md) |
| `tests/mcpauth/` | MCP server-auth conformance through the Go SDK, mcpkit and the TS SDK | [mcpauth](tests/mcpauth/CLAUDE.md) |
| `docs/site/` | Docsite | [docs/site/CLAUDE.md](docs/site/CLAUDE.md) |
| `examples/` | 10 progressive examples with demokit | [examples/README.md](examples/README.md) |

Go workspace with sub-modules for heavy backends (`go.work`). Published `go.mod` files carry no `replace` directives, so every command is `go install`-able; `go.work` and its release-managed `replace` block make the checkout build as one workspace. `GOWORK=off` builds a sub-module against the tagged versions it requires. Consumer guide: [docs/MIGRATION.md](docs/MIGRATION.md).

## Build & test

```bash
make test          # Unit tests
make e2e           # E2E tests (in-process)
make testkcl       # Keycloak + RAR interop (auto-starts Docker)
make testoidf      # OIDF FAPI 2.0 + Basic OP plans
make conformance   # every suite in conformance/suites.yaml, one line each (SUITE=x for one)
make testpg / testds  # GORM on Postgres, GAE on the Datastore emulator
make testgh        # outbound against real GitHub (never in CI; see outbound/CLAUDE.md)
make testall       # Everything + report
make fmt / fmtcheck / vulncheck
make release V=vX.Y.Z  # then make pushrelease / verify-install
```

## Architecture decisions

- **Client library, not a proxy.** `cmd/oneauth-server/` is a reference deployment, not the product.
- **gRPC-shape interfaces**: `MethodName(ctx, *XRequest) (*XResponse, error)` for every transport-agnostic interface. HTTP handlers are thin wrappers (#110, #175).
- **Storage-agnostic, composed interfaces.** Each impl takes only the deps it needs, with no god objects.
- **Grouped hooks**: `TokenHooks`, `AuthHooks`, `ClientHooks`, `SecurityHooks` (`apiauth/hooks.go`).
- **`Mount*` helpers** for any feature mounting more than one route (`MountASMetadata`, `MountDeviceFlow`, `MountAuthorize`). The helper owns routes and handlers, and callers pass deps and integration points.

Rationale in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Shipped vs in flight in [docs/ROADMAP.md](docs/ROADMAP.md).

## Conventions

- Exported API gets doc comments with the contract's why (error mapping, idempotency, atomicity). Match the most polished precedent, not the nearest.
- Security tests carry `// See:` links to RFC/CVE/CWE references.
- New test groups go in their own `_test.go` file.
- `docs/oauth/` guides cite code by symbol, never `file.go:NNN`.
- Examples split into `main.go` (server, `--serve`) and `walkthrough.go`. `make walkthrough` regenerates `WALKTHROUGH.md`.
- `gh` needs `GH_TOKEN="$GH_PERSONAL_TOKEN"`.
- Use `#N` backlinks only when the cross-reference is the audit trail you want, and "issue N" otherwise.

## Repo-wide gotchas

- **gofmt is a CI gate** for every tracked `.go` file in every module. `make fmt` fixes it, and the cleanup commit is in `.git-blame-ignore-revs`.
- **Keep the `go` directive in lock-step** across `go.work` and every module, since stdlib CVEs need it. `make vulncheck` is the gate.
- **CodeQL reports errors as PR checks.** It flags `ParseUnverified` on request input even after verification elsewhere, and SHA-256 over a field named like a secret. Take claims from the validator's `TokenInfo`, and compare keys directly.
- **Every module releases on one tag.** `make release V=vX` writes one commit that sets every `github.com/panyam/oneauth*` require to `vX` and tags all modules on it; `make pushrelease` pushes the tags, records their `go.sum` hashes (a release commit can't hold them), then pushes main; `make verify-install` follows. Between releases the requires name the last tag, and `verify-submodule-deps` (part of `make test`) fails on drift or on a `replace` in a published `go.mod`. New root API can be used by a sub-module in the same PR.
- **CI runs every module's tests on Windows** (no `-race`). File names, `filepath.IsAbs` and Unix mode bits differ there. A Unix-only test needs `t.Skip` with the reason, and an OS-specific behavior gets a `_windows_test.go` (#502, #505).
- **Local `main` can be locked by another worktree.** Cut branches from `origin/main` (`git checkout -b feat/X origin/main`).

## Issues, gaps, memories

- Work is ranked by mission (`~/.claude/skills/retriage/queue.sh`). The active mission is #489 (every applicable external conformance suite, run from `make conformance`); JARM (#409) is parked. A new issue gets `P0` to `P3` and a mission link or `waiting` with its trigger. Status lives in issues and [NEXTSTEPS.md](NEXTSTEPS.md).
- Gap analyses: [Auth0](docs/gaps/AUTH0_GAP_ANALYSIS.md), [Authlete](docs/gaps/AUTHLETE_GAP_ANALYSIS.md) (#163).
- Federated auth (oneauth + massrelay + excaliframe): [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Design lessons are in `memories/` (index `memories/MEMORY.md`). Save memories there, not in `~/.claude/`.
