# OAuch run against oneauth-server

[OAuch](https://github.com/DistriNet/OAuch) (DistriNet, MIT) checks an OAuth 2.0 / OpenID Connect authorization server against RFC 6749, 6750, 6819, 7009, 7636, 9700 (the Security BCP) and OIDC Core, and against the threats in RFC 6819 and the BCP. It has only an interactive web UI, so it runs by hand, and `conformance/suites.yaml` records it as a `manual` suite (issue 497).

## Last run

- **When:** 2026-11-20, against the reference server built from the commit in `conformance/suites.yaml`.
- **Server config:** `tests/oauch/oneauth-oauch.yaml`: code flow, OIDC, PKCE required, remembered consent, ES256.
- **Documents selected:** RFC 6749, 6750, 6819, 7009, 7523, 7636, 9700, OIDC.
- **Outcome:** 107 tests run, 2 still pending (OAuch's timed tests, which need a resume after 10 minutes). 9 failed:
  - 3 of 55 mandatory;
  - 3 of 16 recommended;
  - 3 of 7 optional.
- **Threats:** 30 mitigated, 4 partly mitigated, 2 not mitigated.
- **Since the first run:** the first run, at `c46fedf`, failed 13. Issue 519 fixed the four it found in the code (repeated parameters at `/authorize` and the token endpoint, client credentials in the request URI, and the redirect fragment), and those four now pass.

| Document | Failure rate |
|---|---|
| RFC 6749 | 5.0 % |
| RFC 6750 | 30.0 % |
| RFC 7636 | 15.4 % |
| RFC 6819 | 11.1 % |
| RFC 7009 | 12.5 % |
| RFC 9700 | 19.2 % |
| OIDC | 0.0 % |
| RFC 7523 | not supported for this run's clients (see below) |

## Each failure, and what it means

| OAuch test | Level | Verdict |
|---|---|---|
| Trusted token certificate | mandatory | Test setup. The run uses the OIDF test CA's certificate, which no browser or OS trusts. A deployment with a public certificate passes. |
| Trusted authorization certificate | mandatory | Test setup, as above. |
| Trusted API certificate | mandatory | Test setup, as above. |
| Are the access tokens bearer tokens? | recommended | Configuration. oneauth supports DPoP (`dpop.enabled`, `dpop.require`); this run's config leaves it off, as most deployments start. |
| Does the server support asymmetric client authentication | recommended | Test setup. oneauth supports `private_key_jwt` with inline keys or `jwks_uri` (issue 507); OAuch needs a client certificate or key configured to test it, and the run used secret-based clients. |
| Does the server support RFC8705 (mTLS) | recommended | Not supported: issue 335. |
| Are refresh tokens revoked after access token revocation | optional | Accepted. RFC 7009 §2.1 lets the AS revoke the refresh token too (MAY); oneauth revokes only the token presented. |
| Is JAR supported at the authorization endpoint | optional | Not supported: issue 338. |
| Does the server support Post Form response mode | optional | Not supported: #500. |

The two threats not mitigated are "Eavesdropping access tokens on transport" at the token endpoint and at the API. Both depend on the certificate and bearer-token findings above, so they come from the test certificate and DPoP being off, not from code.

## Bugs the first run found

Running OAuch meant driving a real Chrome through the flow, which the OIDF harness doesn't (its browser ignores CSP and opener policies). Two server headers broke every browser authorization, and issue 497's PR fixed both:

- **`form-action 'self'` in the CSP.** Chrome applies `form-action` to every redirect a form submission causes. The login and consent forms both end in a redirect to the client's `redirect_uri`, on another origin, so Chrome blocked every authorization at that step. The CSP now has no `form-action`, which doesn't fall back to `default-src`.
- **`Cross-Origin-Opener-Policy: same-origin` on the authorization pages.** A client that opens `/authorize` in a popup (an SPA's popup login, or OAuch) loses its `window.opener` when the popup reaches oneauth, so the callback can't hand the result back. `/authorize` and `/auth/` pages now send `unsafe-none`; every other page keeps `same-origin`.

## Running it again

1. Build OAuch's image from a clone: `cd src/OAuch && docker build -t oauch:local .` (it has no published image).
2. Start oneauth-server with `tests/oauch/oneauth-oauch.yaml`. It answers at `https://localhost.emobix.co.uk:8895`, a name that resolves to 127.0.0.1 for the browser.
3. Start OAuch with that name pointing at the host, on a port the OIDF harness doesn't use:
   ```
   docker run -d --name oauch -p 9443:443 --add-host localhost.emobix.co.uk:<host IPv4> -v <dir>:/db oauch:local
   ```
   OAuch keeps its sites in SQLite under `/db`, so the volume is required, and it keeps the site's settings between runs. On Docker Desktop the host's IPv4 is what `host.docker.internal` resolves to inside a container. oneauth-server listens on IPv4 only, so the IPv6 `host-gateway` address won't do.
4. Sign up a user at `/auth/signup`, and register two confidential clients through `POST /apps/dcr` with redirect URI `https://localhost:9443/Callback`.
5. In OAuch (`https://localhost:9443`), add a site with metadata URL `https://localhost.emobix.co.uk:8895`. Set the callback URI, both clients, the scope `openid profile email offline_access` and the documents above, then run the test set.
6. Log in and approve consent in the popup once per client. When the popup shows oneauth's error page (an expected refusal), press OAuch's "Stalled test" to move on. The test config keeps users in memory, so after a server restart clear the browser's cookies for the server first. Otherwise the popup skips login with a session for a user the server no longer has, userinfo fails, and OAuch skips every RFC 6750 test.
7. Update the `oauch` entry in `conformance/suites.yaml` and this page.

Automating the run is waiting on OAuch growing an API, or on someone scripting its UI.
