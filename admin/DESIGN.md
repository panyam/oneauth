---
package: admin
purpose: Admin authentication, app/client registration (proprietary + RFC 7591 DCR + RFC 7592 management), and resource-token minting for OneAuth's federated auth flow.
last_rebuilt: ca8a742623b748f06d2564dce90465d1eeb10c6d
entities:
  - name: AdminAuth
    kind: interface
    role: Authenticates inbound admin requests to protected endpoints (registration, rotation).
    why: Single-method interface so the auth strategy (none, API key, future Bearer) is swappable without touching handler code; deliberately request-shaped (*http.Request) since it gates the HTTP edge, not the transport-agnostic core.
  - name: NoAuth
    kind: struct
    role: AdminAuth that allows everything.
    why: Exists so dev/test wiring is explicit rather than passing nil; doc-marked dev/test-only to discourage production use.
  - name: APIKeyAuth
    kind: struct
    role: AdminAuth validating a shared key in the X-Admin-Key header.
    why: Uses subtle.ConstantTimeCompare to avoid timing side-channels on the key; distinguishes missing (Unauthorized) from wrong (Forbidden) so callers get the right 401-vs-403.
  - name: ErrAdminUnauthorized / ErrAdminForbidden
    kind: sentinel error
    role: Admin-auth failure modes (missing credential vs rejected credential).
    why: withAuth maps these to 401 vs 403 respectively — keeping them distinct here is what lets the HTTP layer differentiate.
  - name: AppRegistrationStore
    kind: interface
    role: Persistence contract (source of truth) for app registration metadata — Save/Get/List/Delete.
    why: Decouples AppRegistrar from any one backend; AppRegistrar keeps a hot-path in-memory cache hydrated from this on construction, so the store is authoritative but not on the read path. Backends live in stores/fs and stores/gorm (issues 166/167).
  - name: InMemoryAppStore
    kind: struct
    role: Process-local AppRegistrationStore for tests/dev.
    why: Clones on every Save/Get/List so callers can never mutate stored state through a returned pointer (defensive copy guards the map); state is lost on restart by design.
  - name: ErrAppNotFound
    kind: sentinel error
    role: Returned by Get/Delete when a client_id is absent.
    why: Shared sentinel so admin handlers (404) and the manager methods agree on "not found" without string matching.
  - name: AppRegistration
    kind: struct
    role: The persisted metadata record for a registered app (proprietary + RFC 7591/7592 fields).
    why: DCR/7592 fields are persisted from issue 165 onward even before the management protocol used them — schema stability so later issues populate fields without a migration. Empty for legacy /apps/register entries.
  - name: AppRegistrar
    kind: struct
    role: Central embeddable HTTP handler + business core; implements both ClientRegistrar (admin) and ClientRegistrationManager (self-service), backed by KeyStore + AppRegistrationStore + optional KidStore.
    why: One type implements two interfaces deliberately — same domain (registrations), two security models. KidStore is typed as the keys.KidStorage interface (not concrete *KidStore) so a persistent backend plugs in without losing in-memory compatibility.
  - name: ClientRegistrar
    kind: interface
    role: Transport-agnostic ADMIN surface — Register (7591), RegisterLegacy (proprietary), ListClients, GetClient, DeleteClient, RotateSecret.
    why: Post-auth by design — it expresses *what* admin ops exist, not *who* may invoke them (the HTTP wrapper enforces AdminAuth first). gRPC-shaped (ctx, *Req)->(*Resp, error) per the project-wide convention (issues 172/175).
  - name: ClientRegistrationManager
    kind: interface
    role: Transport-agnostic SELF-SERVICE surface (RFC 7592) — Get/Update/DeleteRegistration, authed by registration_access_token.
    why: Split from ClientRegistrar precisely because the security model differs (client acts on its own registration vs operator across all). Same (ctx, *Req)->(*Resp) shape so it maps cleanly to gRPC codegen later.
  - name: ErrUnauthorized
    kind: sentinel error
    role: The single failure mode for any auth problem in the management protocol.
    why: Uniform on purpose — distinguishing "unknown client_id" from "wrong token" would turn /apps/dcr/{client_id} into an identifier-enumeration probe.
  - name: ErrInvalidClientMetadata
    kind: sentinel error
    role: Authenticated-but-invalid request body in the management/DCR surface (HTTP 400).
    why: Kept distinct from ErrUnauthorized because by this point the caller has proven token possession; collapsing them would be needlessly cryptic and break the 400-vs-401 mapping.
  - name: ErrInvalidPublicKey / ErrPublicKeyRequired
    kind: sentinel error
    role: Asymmetric-registration failures (bad PEM / missing PEM) on the admin surface.
    why: There is no server-side keypair generation — asymmetric clients MUST supply their own PEM, so these guard that contract and map to HTTP 400.
  - name: DCRHandler
    kind: struct
    role: HTTP wrapper implementing RFC 7591 DCR at POST /apps/dcr; parses, authenticates, delegates to AppRegistrar.Register, formats response.
    why: Thin adapter only — all protocol logic lives behind ClientRegistrar. IssuerBaseURL falls back to request scheme+Host when unset (fine for tests, unreliable behind proxies — production should set it explicitly).
  - name: DCRRequest
    kind: struct
    role: RFC 7591 registration request body, reused as the RFC 7592 §2.2 PUT update body.
    why: One struct for register and update — ClientID is ignored on register (server assigns) but required and path-validated on PUT, so the same shape serves both verbs.
  - name: DCRResponse
    kind: struct
    role: RFC 7591 registration response extended with RFC 7592 §3 management credentials.
    why: Carries registration_access_token + registration_client_uri so a freshly registered client can immediately self-manage; the GetRegistration read path deliberately omits client_secret to avoid re-disclosing symmetric material on every read.
  - name: DCRManagementHandler
    kind: struct
    role: HTTP transport adapter for the RFC 7592 verb trio (GET/PUT/DELETE) at /apps/dcr/{client_id}.
    why: 405 path is computed without consulting client_id or auth so it leaks no per-client info; PUT enforces body client_id == path client_id and caps body size (64 KiB) before the manager ever sees the request.
  - name: ClientRegistrar request/response types
    kind: struct group
    role: RegisterRequest/Response, RegisterLegacyRequest/Response, List/Get/Delete/RotateSecret Request/Response wrappers.
    why: Wrapper structs (some empty today, e.g. ListClientsRequest, DeleteClientResponse) exist so future fields — paging, filters, confirmation tokens — can be added without changing method signatures, mirroring gRPC's per-method message requirement.
  - name: ClientRegistrationManager request/response types
    kind: struct group
    role: Get/Update/DeleteRegistration Request/Response wrappers.
    why: Same forward-compat rationale; DeleteRegistrationResponse is empty because RFC 7592 §2.3 mandates 204 No Content.
  - name: MintResourceToken
    kind: function
    role: Mints a 15-min resource-scoped JWT for a user on behalf of an app, HS256 with the app secret (back-compat API).
    why: Thin wrapper over MintResourceTokenWithKey so the common shared-secret path stays a one-liner while the keyed variant handles all algorithms.
  - name: MintResourceTokenWithKey
    kind: function
    role: Mints a resource JWT with auto-detected signing alg from the key type ([]byte->HS256, *rsa->RS256, *ecdsa->ES256).
    why: Algorithm is inferred from the Go key type rather than a passed-in string, removing a class of "wrong alg for this key" bugs; sets the kid header best-effort (ignores ComputeKid error) so unsigned-kid keys still mint.
  - name: AppQuota
    kind: struct
    role: Per-app quota (MaxRooms, MaxMsgRate) embedded as custom JWT claims.
    why: OneAuth-specific federation quota that RFC 7591 has no field for — only emitted as claims when non-zero (omitempty) so unconstrained tokens stay clean.
depends_on:
  - folder: core
    entities: [AuthorizationDetail]
  - folder: keys
    entities: [KeyRecord, KeyStorage, KidStorage]
  - folder: utils
    entities: [ComputeKid, DecodeVerifyKey, EncodePublicKeyPEM, IsAsymmetricAlg, JWKSet, JWKToPublicKey]
---

## Cross-cutting design notes

**Two interfaces, one implementation, two security models.** `AppRegistrar` satisfies both `ClientRegistrar` (admin, operator-scoped, gated by `AdminAuth` at the HTTP edge) and `ClientRegistrationManager` (self-service, authed by the per-registration `registration_access_token`). The split is intentional — same domain, different "who may act." All four token-comparison sites use `subtle.ConstantTimeCompare`.

**No-enumeration guard runs throughout the management protocol.** Every auth failure mode in Get/Update/DeleteRegistration — missing token, wrong token, unknown client_id, or a registration that simply has no management token (legacy entries) — collapses to `ErrUnauthorized`. This is what keeps `/apps/dcr/{client_id}` from being a valid-identifier probe.

**Store-first write ordering.** Delete and Update persist to the `AppRegistrationStore` *before* mutating the in-memory cache or touching KeyStore credentials. A store failure therefore leaves the registration authoritatively intact and the operation retryable, never stranding key material without a registration to bind it. KeyStore deletion is best-effort (a stranded key is unreachable once the registration is gone); KidStore retention during rotation is *not* best-effort — a persistence failure fails the whole rotation, because silently dropping the old kid would advertise a grace period that doesn't exist and reject in-flight tokens.

**Cache is a read optimization, store is truth.** The `apps` map is hydrated from `Store.ListApps()` on construction and updated synchronously on every write via `SaveRegistration`. Hydration errors at startup are intentionally swallowed (empty cache, no panic) — a transient store hiccup shouldn't crash the host process.

**HTTP layer is uniformly thin.** Handlers (`DCRHandler.ServeHTTP`, the `handleX` methods, `DCRManagementHandler`) only parse, authenticate, delegate to the interface method, then format. RotateSecret's wrapper marshals to a `map[string]any` rather than the typed struct so empty fields drop out and the wire output stays byte-identical to the pre-refactor handler.

**Routing gotcha.** `AppRegistrar.Handler()` relies on Go ServeMux longest-prefix matching: `/apps/dcr/` (7592 management) wins over the `/apps/` catch-all, and exact `/apps/dcr` handles 7591 registration. `extractClientID` rejects nested paths so sub-resources can't accidentally match.

**Legacy surface is on a deprecation path.** `RegisterLegacy` / `/apps/register` carries OneAuth quota fields (MaxRooms/MaxMsgRate) that DCR can't express; removal is tracked under issue 189. UpdateRegistration locks `TokenEndpointAuthMethod` (changing it would require re-keying, out of scope for issue 169 — clients must DELETE and re-register).
