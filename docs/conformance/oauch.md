# OAuch run against oneauth-server

[OAuch](https://github.com/DistriNet/OAuch) (DistriNet, MIT) checks an OAuth 2.0 / OpenID Connect authorization server against RFC 6749, 6750, 6819, 7009, 7636, 9700 (the Security BCP) and OIDC Core, and against the threats in RFC 6819 and the BCP. It has only a web UI. `tests/oauch` drives that UI with playwright-go, so `make conformance` runs it as an `info` suite (issue 567). The first runs were by hand (issue 497).

```
make testoauch                    # or: make conformance SUITE=oauch
```

## How a run works

1. `make upoauch` builds OAuch from a pinned commit (`OAUCH_REF` in the Makefile) and starts it on `https://localhost:9443`, with an empty site database.
2. `scripts/exercise-oauch.sh` starts oneauth-server with `tests/oauch/oneauth-oauch.yaml`: code flow, OIDC, PKCE required, remembered consent, ES256. It answers at `https://localhost.emobix.co.uk:8895`, a name that resolves to 127.0.0.1.
3. `TestOAuch` signs up a user and registers two confidential clients through open DCR. It imports a site into OAuch with those clients and the documents RFC 6749, 6750, 6819, 7009, 7523, 7636, 9700 and OIDC.
4. It runs the test set in headless Chromium. In each popup it logs in and approves consent. When oneauth shows an error page instead of redirecting, which is the expected answer to several of OAuch's attacks, it presses "Stalled test".
5. Two timed tests need a resume 12 to 15 minutes later, after authorization codes and access tokens expire. The run waits and resumes, so it takes about 15 minutes in all.
6. It exports the results and checks each one against `tests/oauch/expected.yaml`. An unlisted test that doesn't pass fails the suite. A listed test that passes gets logged, so its line can come out. The export lands in `test-reports/oauch/oauch-export.json`.

## Last run

- **When:** 2026-11-23, at the commit in `docs/conformance/report.json`.
- **Outcome:** 133 OAuch tests. 87 passed. The other 46 match `expected.yaml`: 22 not implemented and 24 skipped.
- **Since the hand runs:** "Does the server support Post Form response mode" passes now, since issue 500. The hand runs reported OAuch's per-document scores (109 tests and 9 failures on 2026-11-20). The automated run counts every test result, including the feature probes, so its numbers differ.

## The tests that don't pass

`expected.yaml` lists each one with its verdict. By group:

| Verdict | Tests | Why |
|---|---|---|
| Test setup | 3 certificate tests | The run uses the OIDF test CA's certificate, which no browser or OS trusts. A deployment with a public certificate passes. |
| Test setup | asymmetric client auth, JWT client auth, RFC 7523, and 9 `Jwt.*` tests | Both clients use `client_secret_basic`. oneauth supports `private_key_jwt` with inline keys or `jwks_uri` (issue 507), and OAuch needs a client key configured to test it. |
| Test setup | `IsClientIdRequired`, `RequireUserConsent` | They need a public client, and both clients are confidential. |
| Config | bearer tokens, PAR supported and required | The config leaves `dpop.enabled` and `code_flow.par.enabled` off, as most deployments start. |
| Not supported | RFC 8705 (mTLS), JAR | Issues 335 and 338. |
| Accepted | refresh token revoked with the access token | RFC 7009 §2.1 lets the AS revoke the refresh token too (MAY). oneauth revokes only the token presented. |
| By design | implicit, hybrid, password and device grants, and 5 tests built on them | oneauth offers the code flow, and this config leaves the password and device grants off. |
| Secure | plain PKCE, deprecated TLS, token in the URL, and 2 tests that run only when those are allowed | A secure server refuses these. OAuch reports a refusal as "not implemented". |
| Not applicable | 4 `IdTokens.*` tests | ID tokens are ES256 with one audience, so MAC and `azp` checks don't apply. |
| Harness | `InvalidRedirectTest` | oneauth shows an error page for a wrong `redirect_uri` instead of redirecting to it (RFC 6749 §4.1.2.1). OAuch sees that only as a stalled test, so it can't score the refusal. |

## Bugs the first run found

Running OAuch meant driving a real Chrome through the flow, which the OIDF harness doesn't (its browser ignores CSP and opener policies). Two server headers broke every browser authorization, and issue 497's PR fixed both:

- **`form-action 'self'` in the CSP.** Chrome applies `form-action` to every redirect a form submission causes. The login and consent forms both end in a redirect to the client's `redirect_uri`, on another origin, so Chrome blocked every authorization at that step. The CSP now has no `form-action`, which doesn't fall back to `default-src`.
- **`Cross-Origin-Opener-Policy: same-origin` on the authorization pages.** A client that opens `/authorize` in a popup (an SPA's popup login, or OAuch) loses its `window.opener` when the popup reaches oneauth, so the callback can't hand the result back. `/authorize` and `/auth/` pages now send `unsafe-none`; every other page keeps `same-origin`.

The first run also found four bugs in the code, which issue 519 fixed: repeated parameters at `/authorize` and the token endpoint, client credentials in the request URI, and the redirect fragment.

## Looking at a run in OAuch's UI

OAuch keeps running after `make testoauch`. Its sites belong to the throwaway user each browser gets, so a fresh browser doesn't see the run's site. Open `https://localhost:9443`, accept the certificate, and import `test-reports/oauch/oauch-export.json` through "Import site data" to browse the run's results and logs. `make downoauch` stops OAuch, and the next `make upoauch` starts with an empty database.
