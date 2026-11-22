# JWT Secured Authorization Response Mode (JARM)

> **Status:** OpenID Foundation final specification (2022), part of FAPI 1.0 Advanced and FAPI 2.0 Message Signing
> **L-tier / T-tier:** L6 · T1 (authorization response)
> **OneAuth coverage:** Implemented, opt-in. The AS signs (`OneAuthConfig.JARM`), the SDK verifies (`BrowserLoginRequest.ResponseMode`, `client.VerifyAuthorizationResponse`), and DCR takes `authorization_signed_response_alg`
> **See also:** [`FAPI.md`](FAPI.md) · [`RFC_9207.md`](RFC_9207.md) · [`RFC_9126.md`](RFC_9126.md) · [`RFC_7591.md`](RFC_7591.md)

## In one sentence

The authorization server returns its authorization response as one JWT it signs, so the client can check who sent the code and who it was meant for before it uses it.

## What problem does it solve?

| Plain authorization response | JARM |
|---|---|
| `?code=...&state=...` arrives as loose URL parameters that anyone on the path can swap or replay | One `response` parameter, a JWT signed with the AS key |
| The client learns which AS sent it only from RFC 9207's `iss`, which is unsigned | `iss` is a signed claim, checked against the issuer the client discovered |
| A code minted for another client looks the same as one minted for you | `aud` names the client, and a response for anyone else is refused |
| An old response can be replayed | `exp` limits it to about a minute |
| Errors (`access_denied`) can be injected as easily as codes | Errors are signed too |

## Relatable example

A CLI logs in with `oneauth token browser --response-mode jwt`. The user approves at the AS, and the browser arrives at the CLI's loopback with `?response=eyJ...`. The CLI fetches the AS's JWKS, finds the key by the JWT's `kid`, and checks the signature. Then it checks that `iss` is the AS it discovered, that `aud` is its own client_id and that `exp` hasn't passed. Only then does it read `code` and `state` and exchange the code. If someone on the way flips one character of the JWT, the signature check fails and the CLI never contacts the token endpoint.

## Key concepts

- **Response modes.** `jwt` is the default for the response type: `query.jwt` for `code`, and `fragment.jwt` for the implicit types. `query.jwt`, `fragment.jwt` and `form_post.jwt` deliver the JWT the way `query`, `fragment` and `form_post` deliver parameters.
- **The JWT's claims.** `iss`, `aud` and `exp` are required. The response parameters become string claims beside them: `code` and `state`, or `error` and `error_description`.
- **`authorization_signed_response_alg`.** A client registration field (JARM §3) that picks the signing algorithm. `none` is not allowed.
- **Fail closed.** A client that asked for a JARM mode must refuse a response without a valid JWT, even one with a perfectly good plain `code`. Accepting it would let an attacker strip the signature.

## Wire example

Request:

```
GET /authorize?response_type=code&client_id=app_1&redirect_uri=http://localhost:18501/callback
  &response_mode=jwt&state=NrYu...&code_challenge=...&code_challenge_method=S256
```

Response, a redirect with one parameter:

```
HTTP/1.1 302 Found
Location: http://localhost:18501/callback?response=eyJhbGciOiJFUzI1NiIsImtpZCI6Ii4uLiJ9...
```

The JWT's header and claims, as oneauth-server signs them:

```json
{ "alg": "ES256", "kid": "qx0gEPiQTfOgueia30P4pIpVLsMBOhdHSjs4mjihn7w", "typ": "JWT" }
{
  "iss": "http://localhost:18500",
  "aud": "app_1",
  "exp": 1795340066,
  "code": "a1e8d9b4...",
  "state": "NrYu..."
}
```

Discovery advertises it:

```json
{
  "response_modes_supported": ["query", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"],
  "authorization_signing_alg_values_supported": ["ES256"]
}
```

## Where it lands on the OAuth abstraction

- **L6 message signing.** It signs the front-channel response, as JAR (RFC 9101) signs the request.
- **T1 (authorization response).** It changes only how `/authorize` answers, and the token endpoint is unchanged.

## OAuth 2.0 and 2.1 status

Neither OAuth 2.0 nor the OAuth 2.1 draft requires it. RFC 9207's `iss` parameter covers the mix-up attack for most deployments. FAPI 1.0 Advanced and FAPI 2.0 Message Signing require JARM, so a deployment aiming at either needs it.

## OneAuth status

| JARM surface | Status | Where | Notes |
|---|---|---|---|
| `jwt`, `query.jwt`, `fragment.jwt`, `form_post.jwt` at `/authorize` and through PAR | **Implemented** | `AuthorizationHandler.ResponseSigner`, set by `MountAuthorize` | `query.jwt` is refused for the implicit types, like `query`. `fragment.jwt` is offered for `code` too, since §2.3.2 defines it for every response type |
| Opt-in | **Implemented** | `OneAuthConfig.JARM`; reference server `code_flow.jarm.enabled` | Needs an RS256 or ES256 key. `NewOneAuth` panics on an HMAC secret, and the reference server refuses to start |
| Signing | **Implemented** | `NewJWTAuthorizationResponseSigner`, `AuthorizationResponseSigner` | The AS key, with the `kid` the JWKS publishes. `exp` is 60 seconds (`DefaultAuthorizationResponseExpiry`, `JARMConfig.Expiry`). Signing happens at delivery, and a response that can't be signed shows a `server_error` page rather than going out unsigned |
| Signed errors | **Implemented** | `AuthorizationHandler.ErrorResponse` | Errors that go to the redirect_uri are signed. Errors shown on the AS's own page, such as a bad redirect_uri, are not |
| RFC 9207 `iss` | **Moved inside** | `AuthorizationHandler.newResponse` | A JARM response carries `iss` as a claim and not on the URL |
| Metadata | **Implemented** | `ASServerMetadata.AuthorizationSigningAlgValuesSupported`, `OneAuth.AuthorizationSigningAlgs` | The reference server sets both fields when JARM is on |
| `authorization_signed_response_alg` (§3) | **Implemented** | `core.AppRegistration`, `admin.DCRRequest`, every app store, CIMD | DCR accepts only `AppRegistrar.AuthorizationSigningAlgs`, so `none` is refused. A registered alg the AS can't sign with fails the response with `server_error` |
| Registration turning JARM on | **Not done, on purpose** | None | The registered alg sets the algorithm only. The client still asks with `response_mode=jwt`, as Keycloak does, so existing clients don't change behavior |
| Default alg | **AS key's alg** | `NewJWTAuthorizationResponseSigner` | §3 says RS256 when a client registers none. An AS with an EC key can't sign RS256, so oneauth uses its own algorithm |
| PS256 with an RSA key | **Not implemented** | None | FAPI 2.0 prefers PS256 over RS256. The JWKS lists the RSA key under RS256, and a verifier that checks a key's alg against the token's (oneauth's does) would refuse PS256. Use an ES256 key for FAPI |
| Client verification | **Implemented** | `client.VerifyAuthorizationResponse`, `BrowserLoginRequest.ResponseMode`, `oneauth token browser --response-mode` | §2.4's checks: an asymmetric signature by a key in the JWKS, `iss`, `aud`, `exp`. Failures wrap `ErrUnverifiedAuthorizationResponse`. An `error` inside a verified JWT is a `*CallbackError` |
| `form_post.jwt` at the client | **Implemented** | `LoginWithBrowser` | The loopback reads a POSTed form. `fragment` modes fail before the browser opens, since a fragment never reaches the loopback |
| DCR from the SDK and CLI | **Implemented** | `client.ClientRegistrationRequest.AuthorizationSignedResponseAlg`, `oneauth dcr register --authorization-signed-response-alg` | |
| Encrypted responses (`authorization_encrypted_response_alg`) | **Not implemented** | None | Out of the JARM mission. A consumer asking for it would reopen it |

Two runs check it end to end. `make exercise-jarm` (the `jarm` suite in `make conformance`) logs in against oneauth-server and against Keycloak, and refuses a response with one character of its signature flipped. `TestKeycloak_JARMLogin` logs in with all three loopback modes against Keycloak's PS256 responses.

## When NOT to use it

- **Clients that can't verify JWTs.** A client that would accept the response without checking it gets nothing over a plain response, and loses the error details it could read from the URL.
- **Deployments that RFC 9207 already covers.** If the threat is the mix-up attack alone, `iss` on a plain redirect handles it with less machinery.
- **Responses that must stay secret from the browser.** JARM signs and doesn't encrypt, so anyone holding the URL can read the code.

## Related specs

- [FAPI](FAPI.md) covers FAPI 1.0 Advanced and FAPI 2.0 Message Signing, which require JARM.
- [RFC 9207](RFC_9207.md) covers the unsigned `iss` parameter, which JARM's `iss` claim replaces.
- [RFC 9126](RFC_9126.md) covers PAR, which carries `response_mode=jwt` like any other parameter.
- [RFC 7591](RFC_7591.md) covers DCR, where `authorization_signed_response_alg` is registered.
- [RFC 9101](RFC_9101.md) covers JAR, the signed request that pairs with JARM in FAPI Message Signing (not implemented, issue 338).

## Spec links

- [JARM (OpenID Foundation)](https://openid.net/specs/oauth-v2-jarm.html)
- [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0.html)
