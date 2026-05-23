// Package admin owns OneAuth's client-administration surface — RFC 7591
// Dynamic Client Registration, RFC 7592 registration management, the
// proprietary /apps registry, admin-side CRUD, signing-key rotation with
// grace periods, and resource-token minting.
//
// The package is built around the gRPC-shape convention used across OneAuth:
// every transport-agnostic operation is a MethodName(ctx, *Req) (*Resp, error)
// method on an interface, and HTTP handlers are thin wrappers that parse,
// authenticate, delegate, and format. Two interfaces split the same domain
// (client registrations) by security model. ClientRegistrar is the ADMIN
// surface — operators acting across all registrations, gated by AdminAuth at
// the wrapper, with the interface itself unauthenticated by design.
// ClientRegistrationManager is the SELF-SERVICE surface (RFC 7592) where a
// registered client acts on its own registration, authenticated by the
// registration_access_token issued at registration time. AppRegistrar is the
// single concrete type implementing both; it persists through an
// AppRegistrationStore (the source of truth) while serving reads from a
// hot-path in-memory cache that is hydrated on construction and updated
// synchronously on every write. KeyStore holds the signing material and an
// optional KidStore retains superseded keys during rotation grace periods so
// in-flight tokens stay verifiable. Resource-token minting is a standalone
// concern: MintResourceToken / MintResourceTokenWithKey produce short-lived
// resource-scoped JWTs (auto-selecting HS256 / RS256 / ES256 from the key
// type) carrying scopes, per-app quota, and RFC 9396 authorization details.
// The package deliberately does NOT own end-user login, token issuance for
// the OAuth grants, or introspection/revocation — those live in localauth
// and apiauth. It also does not implement persistent stores; FS/GORM/GAE
// backends for AppRegistrationStore live under stores/.
//
// ENTITIES
//
// ClientRegistrar — Transport-agnostic ADMIN client surface (Register,
// RegisterLegacy, ListClients, GetClient, DeleteClient, RotateSecret). Methods
// are post-auth: the HTTP wrapper enforces AdminAuth before invoking them.
//
// ClientRegistrationManager — Transport-agnostic SELF-SERVICE management
// surface (RFC 7592): GetRegistration, UpdateRegistration, DeleteRegistration,
// each authenticated by the client's own registration_access_token. Same
// domain as ClientRegistrar, different security model — hence a second
// interface.
//
// AppRegistrar — Embeddable http.Handler and concrete implementation of both
// interfaces. Backed by AppRegistrationStore + keys.KeyStorage + optional
// keys.KidStorage; serves reads from an in-memory apps cache hydrated from
// the store on construction.
//
// AppRegistrar.Register — RFC 7591 DCR. Assigns client_id, allocates a
// symmetric secret or stores a caller-supplied JWK, issues RFC 7592 §3
// management credentials. ErrInvalidClientMetadata maps to HTTP 400;
// other errors bubble up as HTTP 500.
//
// AppRegistrar.RegisterLegacy — Proprietary /apps/register path carrying
// OneAuth-specific MaxRooms / MaxMsgRate quota fields DCR cannot express.
// Eventual removal tracked under issue #189.
//
// AppRegistrar.ListClients — Admin read of every registration. Returned
// entries are clones so callers cannot mutate the cache.
//
// AppRegistrar.GetClient — Admin read of a single registration. Reachable
// only by AdminAuth-passing callers; distinct from
// ClientRegistrationManager.GetRegistration.
//
// AppRegistrar.DeleteClient — Admin delete. Persists the store deletion
// before invalidating cache / credentials so a store error leaves the
// registration intact and the call retryable.
//
// AppRegistrar.RotateSecret — Rotates the signing key (new secret for
// symmetric algs, caller-supplied PEM for asymmetric). When KidStore is
// configured the previous key is retained for the grace period; a retention
// persistence failure fails the whole rotation.
//
// AppRegistrar.GetRegistration — RFC 7592 read. Returns the uniform
// ErrUnauthorized for every auth failure mode so the endpoint cannot be
// probed for valid client_ids; client_secret is omitted from the response.
//
// AppRegistrar.UpdateRegistration — RFC 7592 §2.2 full-replacement update.
// Rotates the registration_access_token and returns the new value;
// TokenEndpointAuthMethod is a locked field and changes return
// ErrInvalidClientMetadata.
//
// AppRegistrar.DeleteRegistration — RFC 7592 §2.3 self-service delete.
// Removes the registration and deletes the signing key so already-issued
// tokens fail signature validation; store deletion happens first.
//
// AppRegistrar.SaveRegistration — Persists to Store then updates the cache.
// Cache update is gated on store success so the cache cannot drift ahead of
// durable state.
//
// AppRegistrar.RLockApps — Calls fn with a read-locked view of the
// in-memory apps map without exposing the lock externally.
//
// AppRegistrar.Handler — http.Handler wiring /apps/register, /apps/dcr,
// /apps/dcr/{client_id}, and the /apps CRUD + rotate routes. Relies on
// ServeMux longest-prefix matching so /apps/dcr/ wins over /apps/.
//
// AppRegistration — Persisted registration metadata: client_id, signing alg,
// quota, RFC 7591 / 7592 client-metadata fields, and the
// registration_access_token. May be partly empty for legacy /apps/register
// entries.
//
// AppRegistrationStore — Persistence boundary (SaveApp, GetApp, ListApps,
// DeleteApp); the source of truth behind AppRegistrar's cache. Persistent
// backends live in stores/.
//
// InMemoryAppStore — Process-local AppRegistrationStore for tests/dev. Clones
// values on read and write so the stored map cannot be mutated through
// returned pointers; state is lost on restart.
//
// DCRHandler — HTTP adapter for RFC 7591 registration. Delegates to
// AppRegistrar.Register; falls back to the request scheme+Host for the
// registration_client_uri when IssuerBaseURL is unset (set it explicitly
// behind proxies).
//
// DCRManagementHandler — HTTP adapter for RFC 7592 GET/PUT/DELETE on
// /apps/dcr/{client_id}. Delegates to a ClientRegistrationManager;
// unsupported methods return 405 with an Allow header and leak no
// per-client information.
//
// DCRRequest — RFC 7591 registration body, reused as the RFC 7592 §2.2
// update body. ClientID is ignored on register (server assigns) but
// required and matched against the URL path on PUT.
//
// DCRResponse — RFC 7591 response extended with the RFC 7592 §3 management
// credentials. Reads via GetRegistration omit client_secret to limit the
// disclosure window if the access token is logged or proxied.
//
// AdminAuth — Authentication seam for admin requests; Authenticate(r)
// returns nil when allowed. NoAuth allows everything (dev/test only).
// APIKeyAuth validates the X-Admin-Key header with a constant-time compare.
//
// AppQuota — OneAuth-specific MaxRooms / MaxMsgRate carried as custom
// claims in minted resource tokens so downstream services do not need a
// second lookup.
//
// MintResourceToken / MintResourceTokenWithKey — Mint short-lived
// (15-minute) resource-scoped JWTs for a user on behalf of a registered app.
// The WithKey form auto-detects the signing algorithm from the key type and
// sets a kid header so resource servers can select the verification key.
//
// RegisterRequest / RegisterResponse, RegisterLegacyRequest /
// RegisterLegacyResponse, ListClientsRequest / ListClientsResponse,
// GetClientRequest / GetClientResponse, DeleteClientRequest /
// DeleteClientResponse, RotateSecretRequest / RotateSecretResponse,
// GetRegistrationRequest / GetRegistrationResponse,
// UpdateRegistrationRequest / UpdateRegistrationResponse,
// DeleteRegistrationRequest / DeleteRegistrationResponse — wire-agnostic
// envelopes for the interface methods, wrapped per the gRPC-shape convention
// so future fields do not break method signatures.
//
// ErrAppNotFound, ErrUnauthorized, ErrInvalidClientMetadata,
// ErrInvalidPublicKey, ErrPublicKeyRequired, ErrAdminUnauthorized,
// ErrAdminForbidden — sentinel errors mapped to HTTP status codes by the
// wrappers. ErrUnauthorized is deliberately uniform across all RFC 7592
// failures so the endpoint cannot be probed for valid client_ids.
//
// NewInMemoryAppStore, NewAppRegistrar, NewAppRegistrarWithStore,
// NewNoAuth, NewAPIKeyAuth — constructors. NewAppRegistrarWithStore
// hydrates the in-memory cache from store.ListApps; a transient startup
// error is swallowed (empty cache) so a flaky store does not crash the
// host process.
//
// FLOWS
//
// See diagrams.md for sequence diagrams of: RFC 7591 Dynamic Client
// Registration, RFC 7592 management (read / update / delete), and
// secret/key rotation with grace-period retention.
package admin
