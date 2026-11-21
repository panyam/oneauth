# OAuth Client ID Metadata Document (CIMD)

> **Status:** Internet-Draft (draft-ietf-oauth-client-id-metadata-document-03, November 2026)
> **L-tier / T-tier:** L2 · T0 (setup / registration)
> **OneAuth coverage:** Implemented, opt-in (`apiauth.CIMDAppStore`, `OneAuthConfig.ClientIDMetadataDocuments`)
> **See also:** [`RFC_7591.md`](RFC_7591.md) · [`RFC_8414.md`](RFC_8414.md) · [`RFC_7523.md`](RFC_7523.md)

## In one sentence

A client uses an https URL it controls as its `client_id`, and the authorization server fetches the client's metadata from that URL instead of needing the client registered first.

## What problem does it solve?

| With pre-registration or DCR | With CIMD |
|---|---|
| Each client registers with each AS before its first login | The client publishes one JSON document, and any AS that supports CIMD reads it |
| DCR (RFC 7591) gives every AS its own copy of the client, and each one drifts | One document is the source of truth, and an AS re-reads it when its cache expires |
| An open DCR endpoint lets anyone create clients, so ASes often close it | Nothing is created. The AS reads the document on demand and keeps only a cache |
| The consent page shows a `client_name` the client chose | The consent page can show the host that publishes the document, which the client can't fake |

The MCP authorization spec (2025-11-25) says an authorization server SHOULD support CIMD. An MCP client meets authorization servers it has never seen, often on a user's laptop, and registering with each one first doesn't scale.

## Relatable example

A coding agent wants to call an MCP server whose authorization server is oneauth. The agent's vendor publishes this at `https://agent.example/oauth/client.json`:

```json
{
  "client_id": "https://agent.example/oauth/client.json",
  "client_name": "Example Agent",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "none"
}
```

The agent sends the user to `/authorize` with that URL as `client_id`. oneauth fetches the document, checks it, and shows the consent page. The page says `agent.example` publishes the client's details, and that approving sends the user to `127.0.0.1`. The agent then redeems the code with PKCE, like any public client.

## Key concepts

- **The URL is the identity.** The AS compares `client_id` values as exact strings and never normalizes them (§3). The document's own `client_id` must equal the URL it came from.
- **No shared secrets.** A document must not carry `client_secret`, and its auth method can't be `client_secret_basic`, `client_secret_post` or `client_secret_jwt` (§4.1, §5). A client authenticates with `none` (plus PKCE) or with `private_key_jwt`, using keys in `jwks` or at `jwks_uri`.
- **The default auth method is `none`.** RFC 7591's default of `client_secret_basic` doesn't apply.
- **Fetching is guarded.** The AS follows no redirect, accepts only a 200, reads at most 5 KB, and refuses special-use addresses in production (§6, §10.7, §10.11).
- **Caching follows HTTP.** The AS may cache a document per RFC 9111, within bounds it picks. It must not cache a failure, and a transient failure shouldn't end trust in a copy cached earlier (§6.1, §6.2).

## Wire example

```
GET /authorize?response_type=code
    &client_id=https%3A%2F%2Fagent.example%2Foauth%2Fclient.json
    &redirect_uri=http%3A%2F%2F127.0.0.1%3A51234%2Fcallback
    &code_challenge=...&code_challenge_method=S256&state=...

    (the AS fetches https://agent.example/oauth/client.json, Accept: application/json)

POST /api/token
grant_type=authorization_code&code=...&code_verifier=...
&client_id=https%3A%2F%2Fagent.example%2Foauth%2Fclient.json
&redirect_uri=http%3A%2F%2F127.0.0.1%3A51234%2Fcallback
```

The AS's metadata advertises support:

```json
{ "client_id_metadata_document_supported": true }
```

## Where it lands on the OAuth abstraction

- **L2 lifecycle and registration.** It sits beside DCR as a way for a client to become known to an AS.
- **T0 (setup).** The AS reads the document when the client first shows up, then from its cache.

## OAuth 2.0 and 2.1 status

CIMD is an Internet-Draft from the IETF OAuth working group, and neither OAuth 2.0 nor the OAuth 2.1 draft mentions it. It builds on 2.1's defaults. Public clients use PKCE, and confidential clients use asymmetric keys rather than shared secrets.

## OneAuth status

| CIMD surface | Status | Where | Notes |
|---|---|---|---|
| URL `client_id` at `/authorize`, the token endpoint, userinfo and consent | **Implemented** | `apiauth.CIMDAppStore` | Wraps `core.AppRegistrationStore`, so every client lookup accepts a URL client with no change at the call site |
| Opt-in | **Implemented** | `OneAuthConfig.ClientIDMetadataDocuments`; reference server `code_flow.client_id_metadata_documents` | Off by default. FAPI 2.0 refuses it, since it allows registered confidential clients only |
| URL rules (§3) | **Implemented** | `apiauth.ValidateClientIDMetadataDocumentURL` | https, no userinfo or fragment, a path other than `/`, no dot segments. The AS's own issuer is refused (§10.1) |
| Document rules (§4, §5) | **Implemented** | `CIMDAppStore.GetApp` | `client_id` equals the URL. `client_name` and `redirect_uris` are required, as MCP asks. No secrets or shared-secret methods, and not both `jwks` and `jwks_uri`. `grant_types` and `response_types` are cut down to what the AS supports (§6) |
| `none` and `private_key_jwt` clients | **Implemented** | `apiauth.ClientAuthenticator` | Keys come from the document's `jwks`, or from `jwks_uri` through `ClientJWKSFetcher` |
| Guarded fetch | **Implemented** | `CIMDAppStore` | No redirects, 200 only, 5 KB, 5-second timeout, no cookies. Private addresses only with `AllowPrivateHosts` (reference server `admin_auth.allow_private_client_hosts`), for tests |
| Caching | **Implemented** | `CIMDAppStore` | The response's `max-age`, clamped to 1 minute to 24 hours, 5 minutes when absent. Failures aren't cached. A transient failure serves the cached copy for up to 24 hours after its fetch |
| Errors | **Implemented** | `apiauth.ErrInvalidClientMetadata`, `apiauth.ErrClientMetadataUnavailable` | A bad document is `invalid_client` at the token endpoint and the error page at `/authorize`, never a redirect. An unreachable one is 503 at the token endpoint (§6.1) |
| Consent page shows the hosts | **Implemented** | `AuthorizeVerificationHandler` | The host that publishes the document (§10.6) and the host the user returns to (MCP) |
| `client_id_metadata_document_supported` | **Implemented** | `ASServerMetadata.ClientIDMetadataDocumentSupported` | The reference server sets it with the opt-in |
| Client logos | **Not shown** | None | §10.9 requires the AS to prefetch a logo and serve it from its own host. oneauth drops a URL client's `logo_uri` instead |
| Domain allowlists and trust policy | **Not implemented** | None | §10.8 leaves trust heuristics to the AS. Every valid document is accepted today |
| Grant invalidation when a document changes | **Not implemented** | None | §10.5 says a change may warrant it |

The MCP conformance framework's `mcp-auth-as` run logs in with a URL `client_id` end to end (issue 496, issue 532).

## When NOT to use it

- **Closed deployments with known clients.** Pre-registered clients give the AS a fixed list. CIMD lets any client with a valid document start a login, and the user's consent is the only gate.
- **FAPI 2.0.** It requires registered confidential clients, so oneauth refuses the combination.
- **Clients without a stable https host.** The document has to live at a URL the client controls for as long as its tokens should work.

## Related specs

- [RFC 7591](RFC_7591.md) covers Dynamic Client Registration, the other way a client becomes known without manual setup.
- [RFC 8414](RFC_8414.md) covers AS metadata, which advertises `client_id_metadata_document_supported`.
- [RFC 7523](RFC_7523.md) covers `private_key_jwt`, the confidential-client method a document can declare.
- [RFC 7636](RFC_7636.md) covers PKCE, which a `none` client relies on.
- [RFC 9700](RFC_9700.md) covers the loopback redirect rule that native clients' `redirect_uris` use.

## Spec links

- [Datatracker: draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
- [Draft -03](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-03.html)
- [MCP authorization spec, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
