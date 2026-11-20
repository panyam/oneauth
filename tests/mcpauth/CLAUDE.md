# tests/mcpauth — MCP server-auth conformance

`make exercise-mcpauth SDK=gosdk|mcpkit` (or `make conformance SUITE=mcp-auth-<sdk>`) runs the MCP server-auth scenarios against oneauth-server through one MCP SDK (issue 495). `scripts/exercise-mcpauth.sh` does the setup.

- **Two fixtures, one contract.** `cmd/gosdk-fixture` uses oneauth's `APIMiddleware` for auth, so its failures are oneauth's. `cmd/mcpkit-fixture` uses mcpkit's `ext/auth`, so a check failing only there points at mcpkit. `fixture/` holds the tools and tokens both share.
- **Fixtures build in workspace mode** (`go build ./tests/mcpauth/cmd/...` from the root), so they run the checkout's oneauth. `go.mod` also replaces oneauth with `../..` for `GOWORK=off`.
- **The scenarios run through `driver/run-auth.ts`, not the framework CLI.** At the pinned commit the CLI passes the auth scenarios a RunContext where they take a URL string, and every check fails with "Failed to parse URL from [object Object]" (#521).
- **INFO and SKIPPED checks need `expected-skip` entries** (`suite: mcp` in `tests/conformance/known-gaps.yaml`). A check that didn't run can't pass quietly.
- **mcpkit applies `server.WithMux` routes only in `ListenAndServe`**, not in `Handler()`.
- The framework checkout lives in `MCPCONFORMANCE_DIR` (default `~/.cache/oneauth/mcpconformance`), pinned by `MCPCONFORMANCE_REF`.
