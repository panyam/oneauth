# HANDOFF: mTLS (#335), plus three loose ends

**Written:** 2026-09-20
**Branch at handoff:** `main` @ `35a479d`, clean
**Unreleased:** PAR (#337) and the DPoP nonce protocol (#375) are on `main` but not in a tag. Last release is `v0.1.37`.

Four things are open. The first is a real defect, the second is a five-line
manual step, the third is planned work, the fourth is paperwork.

---

## 1. `make testkcl` fails, cause unknown

`TestKeycloak_Introspection_NoAuthzDetails` fails on the user's machine. The
assertion text was never captured, so this is undiagnosed rather than
understood.

What is known:

- The Keycloak workflow is `workflow_dispatch` only and **has never run**, so
  there is no CI baseline. The failure may predate the DPoP interop work.
- Nothing in the #371 diff has an obvious path to that test. It uses
  `test-confidential` with client_credentials against Keycloak's own
  introspection endpoint; the diff added a separate `test-dpop` client,
  `--features=dpop`, and a new test file.
- `make testkcl` reuses a running container, so a realm edited in
  `realm.json` never reaches a container started earlier.

Next step:

```bash
make downkcl && make upkcl
cd tests/keycloak && GOWORK=off go test -run TestKeycloak_Introspection_NoAuthzDetails -v ./... 2>&1 | tail -20
```

Which assertion fails tells you where to look:

| Failing line | Means | Look at |
|---|---|---|
| `require.Equal(StatusOK, resp.StatusCode)` | introspection refused the client | realm import, `test-confidential` credentials |
| `assert.Equal(true, result["active"])` | token minted but introspected inactive | clock skew, token lifetime |
| `assert.False(hasAD)` | Keycloak returned `authorization_details` | Keycloak version behaviour |

Also run the whole package: if the six `TestKeycloakDPoP_*` tests fail too,
suspect the realm import rather than this test.

---

## 2. A CI workflow patch that has to be applied by hand

`.github/workflows/keycloak-interop.yml` on `main` **still uses a `services:`
block**, so the job would start Keycloak without `--features=dpop` and the
interop tests merged in #385 would fail. They fail loudly by design, so this
is visible rather than silent, but the job is currently broken if dispatched.

The patch could not be pushed: `GH_PERSONAL_TOKEN` has no `workflow` scope.
It lives in PR 385's body and at
`/tmp/claude-0/-workspace-repos-newstack-oneauth-main/6a018dee-b582-4149-911e-82020ba8e4d2/scratchpad/keycloak-workflow.patch`
(scratchpad, so treat the PR body as the durable copy).

```bash
git checkout -b ci/keycloak-dpop-feature main
git apply <the patch>
git commit -am "ci(keycloak): start Keycloak with --features=dpop for the RFC 9449 interop tests"
git push -u origin ci/keycloak-dpop-feature   # needs a credential with workflow scope
```

It converts the `services:` block to an explicit `docker run`, waits for
readiness itself, and dumps container logs on failure.

---

## 3. #335 mTLS — planned, not started

Split it in two. The issue itself says "Effort: L" across eight sub-surfaces.

**PR 1, certificate-bound access tokens.** `apiauth/mtls.go` with a
certificate extractor and `x5t#S256` computation (base64url SHA-256 of the
DER), `core.Confirmation.X5TS256`, emission in `CreateAccessToken`,
enforcement in `enforceBinding`, and
`tls_client_certificate_bound_access_tokens` on AS metadata.

**PR 2, mTLS client authentication.** `tls_client_auth` and
`self_signed_tls_client_auth`, the DCR fields (`tls_client_auth_subject_dn`,
`tls_client_auth_san_*`), and `mtls_endpoint_aliases`.

**Two decisions were put to the user and not answered:**

1. **Where the certificate comes from.** OneAuth usually runs behind a
   TLS-terminating proxy, so the cert arrives as a header, and trusting a
   header means anyone who reaches the server directly can forge a client
   certificate. Recommendation: default to `r.TLS.PeerCertificates` only,
   with a trusted header strictly opt-in and a doc comment stating that the
   proxy must be the sole ingress and must strip client-supplied copies.
2. **Whether to extract `TokenBindingValidator`.** It was deferred twice on
   the grounds that one implementation is a guess about the second. The
   second is now here and the shapes differ: DPoP changes the `Authorization`
   scheme and mints a per-request proof, mTLS keeps `Bearer` and uses the
   transport, and DPoP's §7.2 downgrade check has no mTLS analogue.
   Recommendation: skip the interface. `core.Confirmation` growing a field
   was the extraction that mattered.

**Reference check available:** OpenSSL is installed, so a fixture
certificate's thumbprint can be checked against
`openssl x509 -outform DER | openssl dgst -sha256`, a genuine second
implementation. RFC 8705 §3.1 publishes an example `x5t#S256` value but not
the certificate behind it, so it only pins the format.

---

## 4. Three trackers carry stale claims

Found and evidenced, not edited. Sweeping them is GitHub-only work.

- **#88**, the banking-readiness security audit, says RFC 9126 and RFC 9449
  are "Not currently supported" and that client auth is limited to
  `client_secret_basic` / `client_secret_post`. All four shipped. This is the
  issue someone reads to judge FAPI readiness, so it understates the project
  by four RFCs. Do this one first.
- **#344**, capability gating, lists #294, #295 and #345 as Open; all three
  are closed. Only #346 is still right.
- **#194**, promoting `cmd/oneauth-server`, lists "no full `/authorize`" as a
  rough edge (shipped under #297) and points at #124, which is closed.

---

## Also worth knowing

- **A release is due.** `main` is two features past `v0.1.37`. Both carry
  migration notes: PAR adds a `pushed_authorization_requests` table needing
  `AutoMigrate`.
- **#382** (FS and GAE backends for the authorization-code and pushed-request
  stores) is filed and unstarted. Both contract suites exist, so each backend
  is an implementation plus a one-line `RunAll`.
- **The Keycloak interop suite has never actually executed.** It is written,
  type-checked and merged, but the first real run is still ahead. See item 1.
