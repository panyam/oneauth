// Package saml is a POC SAML 2.0 service-provider integration that wraps
// crewjam/saml behind redirect-style login, logout, and ACS handlers and hands
// off authenticated users through an OAuth2-token-shaped callback.
//
// <!-- design:start -->
// This package owns the wiring between a host HTTP app and an external SAML
// identity provider. It loads the SP signing keypair from on-disk cert/key
// files, fetches IdP metadata over the network at registration time, and builds
// a single process-global samlsp.Middleware. Rather than gating routes with the
// library's RequireAccount middleware, it deliberately exposes explicit
// redirect-driven endpoints (/saml/login, /saml/logout, /saml/acs) so a
// top-level login page can present SAML as one option among several auth
// methods. The result is intentionally a "bastardization" of crewjam/saml: on
// successful assertion it fabricates a placeholder oauth2.Token and invokes the
// host's callback, making SAML masquerade as an OAuth provider for a unified
// login surface. It does NOT issue real OAuth grants, persist users, or manage
// configuration beyond reading env vars and hardcoded cert/key file paths
// (flagged for future configmap migration). State is package-global and read
// once at init, so config changes require a restart.
//
// # ENTITIES
//
// HandleUserFunc — Callback signature invoked after a successful SAML
// authentication; receives an auth type, provider, a (fake) oauth2.Token, the
// extracted userInfo map, and the response/request, so the host app can
// establish its own session. The OAuth2 shape is intentional so SAML plugs into
// the same handoff path as real OAuth providers.
//
// RegisterSamlAuth — Entry point: loads the SP keypair, fetches IdP metadata,
// constructs the samlsp.Middleware (with signed requests), and registers the
// /saml/login, /saml/logout, /saml/acs, and catch-all /saml/ routes on the
// supplied mux.Router. Returns an error if the keypair or IdP metadata cannot be
// loaded.
//
// SAML_ISSUER, SAML_CALLBACK_URL, SAML_LOGIN_URL, SAML_METADATA_URL —
// Package-level configuration sourced from the matching environment variables
// and trimmed at init. SAML_LOGIN_URL is the IdP SSO destination for AuthN
// requests; SAML_METADATA_URL is fetched at registration to configure the SP;
// SAML_ISSUER is reported as the provider name to the callback.
//
// # FLOWS
//
// See diagrams.md for the SP-initiated SSO login flow (request tracking through
// ACS assertion parsing and the user handoff).
// <!-- design:end -->
package saml
