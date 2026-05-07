# OneAuth conformance ratchet

This module hosts the cross-spec conformance fixtures for OneAuth and the
ratchet runner that gates them in CI. See [`docs/CONFORMANCE.md`](../../docs/CONFORMANCE.md)
for the full strategy; this README covers mechanics.

## Running

From the repo root:

```bash
make testconformance         # full run + report at test-reports/conformance.md
```

Reports are always written. The filename is derived from the package
pattern, so a full run and a scoped run produce different files and can
run in parallel without clobbering:

| Command | Report path |
|---|---|
| `make testconformance` | `test-reports/conformance.md` |
| `go run ./cmd/runner -package ./as_metadata/...` | `test-reports/conformance-as_metadata.md` |
| `go run ./cmd/runner -package ./prm/...` | `test-reports/conformance-prm.md` |

Scoped runs go through the runner binary directly:

```bash
cd tests/conformance
GOWORK=off go run ./cmd/runner -package ./as_metadata/...
```

The runner finds `test-reports/` by walking up to the workspace root
(the directory containing `go.work`), so it works the same from any
subdirectory.

## The model

Every test in this module **runs every time**. A test we don't currently
pass is still executed; the runner expects it to fail and looks up the
expected outcome in [`known-gaps.yaml`](known-gaps.yaml). The runner exits
non-zero if observed outcomes drift from the manifest in any direction:

| Observed | In manifest? | Verdict |
|---|---|---|
| PASS | no  | OK (regression-protected) |
| PASS | yes | **fail** — remove the entry to ratchet up |
| FAIL | no  | **fail** — regression |
| FAIL | yes | OK (known gap) |
| SKIP | either | **fail** — `t.Skip()` is forbidden for tests in this suite |

A manifest entry with no observed test result is also a failure (likely
the test was renamed or deleted; the entry is now dead weight).

## Layout

```
tests/conformance/
├── go.mod                      # separate Go submodule, like tests/keycloak
├── known-gaps.yaml             # the manifest
├── as_metadata/                # one suite per directory
│   ├── doc.go                  # cite the RFC(s) being conformed to
│   └── *_test.go
└── cmd/runner/                 # the ratchet runner; not part of the suite
    ├── main.go                 # CLI entrypoint
    ├── manifest.go             # YAML parser + Validate
    ├── diff.go                 # observed-vs-expected diff
    ├── report.go               # Markdown report writer
    └── *_test.go               # unit tests for the runner itself
```

## Adding a test

1. Pick or create a suite directory (`<rfc-shorthand>/`). Add a `doc.go`
   with `// See:` lines pointing at the RFC sections under test.
2. Write the test. Use `*_test.go` in package `<suite>_test` and import
   `github.com/panyam/oneauth/testutil` for an in-process AS — the same
   pattern used by `tests/keycloak/`.
3. Subtests via `t.Run` are first-class entries in the ratchet — they
   give per-assertion granularity. Prefer one `t.Run` per assertion you
   want to track separately.
4. **Do not use `t.Skip()`.** If the assertion can't run today, that's a
   gap; add it to `known-gaps.yaml` and let it fail.

## Adding a known gap

When adding an entry to `known-gaps.yaml`:

```yaml
- suite: as_metadata                              # package basename
  id: TestX/sub_a                                 # full Go test name
  status: expected-fail
  issue: 187                                      # tracking issue (required)
  owner: panyam                                   # required
  reason: |                                       # what's missing, where, and why
    Multi-line OK. Cite file:line of the gap.
  expires: 2026-08-07                             # ISO date; advisory only
```

External-suite entries (OIDF, MCP) use `plan:` + `test:` instead of `id:`.
The runner accepts both shapes, validated at startup.

`expires:` is consumed by the report sort, not the gating runner. A past
`expires:` shows up in `make testconformance-report` flagged with `⚠ expired`,
nothing more. The harder check ("is this gap still real?") is the runner
itself: when the underlying feature ships, the test starts passing and CI
fails until the entry is removed.

## Runner flags

```
runner [flags]
  -manifest string     path to known-gaps.yaml (default ./known-gaps.yaml)
  -package string      Go package pattern (default ./...)
  -report-dir string   directory for reports (default: <workspace>/test-reports)
  -report string       explicit report path (overrides -report-dir)
  -no-report           skip writing a report
```

Default behavior: every run writes to
`<workspace>/test-reports/conformance[-<scope>].md`. Use `-report` to
override the path, `-report-dir` to redirect just the directory, or
`-no-report` to skip.

Exit codes: `0` clean, `1` ratchet diff, `2` invalid manifest, `3` `go test`
infra failure (compile error, etc.).
