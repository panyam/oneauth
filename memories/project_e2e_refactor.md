---
name: project_e2e_refactor
description: Plan to replace Python subprocess-based integration tests with Go in-process e2e tests using httptest.NewServer
type: project
---

Extract server wiring from cmd/*/main.go into reusable NewHandler(config) functions so that:
1. Tests use httptest.NewServer(NewHandler(config)) — no subprocess management
2. All servers (auth + resource + demo) start in-process in milliseconds
3. Race detector works across all servers (same process)
4. No Python dependency for integration tests
5. Demo Docker Compose still works (main() calls NewHandler)

**Why:** Current Python integration tests manage Go binaries via subprocess — fragile, slow (build + start + health-check per server), and resource servers fail to start due to JWKS timing issues.

**How to apply:** Create `tests/e2e/main_test.go` that starts auth + resource servers via httptest.NewServer. Extract handler setup from each cmd/ into an exported function. Keep Python tests for testing against real deployed servers (GAE).
