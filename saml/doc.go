// Package saml registers SAML 2.0 SSO HTTP routes (login, ACS, logout)
// on a gorilla/mux router, wrapping crewjam/saml to fit oneauth's
// redirect-based multi-provider login flow.
//
// The package builds a process-global samlsp.Middleware from an on-disk
// SP keypair and IdP metadata fetched at registration time, then mounts
// explicit /saml/login, /saml/acs, /saml/logout, and catch-all /saml/
// handlers on the caller-supplied router. It deliberately avoids the
// crewjam RequireAccount gate so SAML can sit alongside other providers
// on a top-level /login page. After a successful ACS assertion the
// package fabricates a placeholder oauth2.Token and invokes the host's
// HandleUserFunc, letting SAML reuse the same handoff path as real
// OAuth providers. Configuration is read once from env vars and
// hardcoded cert/key file paths, so changes require a restart; the
// cert/key paths are flagged for future configmap migration.
//
// ENTITIES
//
// RegisterSamlAuth — Loads the SP keypair and IdP metadata, builds the
// samlsp.Middleware, and mounts the /saml/* routes on the supplied
// router. Single entry point applications call to wire SAML into their
// auth router; the custom /saml/login handler exists so SAML is one
// option on a multi-provider /login page rather than gated by
// RequireAccount middleware.
//
// HandleUserFunc — Callback signature invoked after a successful ACS
// assertion, receiving a synthesized oauth2.Token and the extracted
// user attributes. Lets the host application persist the SAML user
// through the same code path it uses for OAuth providers, by masking
// the SAML assertion as an oauth2.Token.
//
// logout — Builds a SAML SLO redirect, deletes the local session, and
// sends the browser to the IdP logout URL. Implements /saml/logout so
// callers can trigger single logout without exposing crewjam internals.
//
// samlMiddleware — Package-level *samlsp.Middleware shared by the
// login, ACS, and logout handlers. The handlers are closures registered
// on the router but need a common ServiceProvider, Session store, and
// RequestTracker; keeping it package-scoped avoids threading it through
// every HandlerFunc.
//
// SAML_ISSUER — Issuer string passed back to the user callback as the
// provider name; sourced from the SAML_ISSUER env var. Identifies which
// IdP authenticated the user when the host app stores or audits
// credentials.
//
// SAML_CALLBACK_URL — Configured callback URL from the
// SAML_CALLBACK_URL env var. Held for future use by callers configuring
// the SP; the active callback comes from the RegisterSamlAuth argument
// today.
//
// SAML_LOGIN_URL — IdP SSO endpoint from the SAML_LOGIN_URL env var,
// used as the destination of MakeAuthenticationRequest. Tells the SP
// where to redirect the browser to start SP-initiated SSO.
//
// SAML_METADATA_URL — IdP metadata URL from the SAML_METADATA_URL env
// var, fetched once at registration to seed the SP. Provides the IdP's
// signing certs and endpoint bindings without requiring them to be
// checked in.
//
// SAML_CERT_FILE — Filesystem path to the SP's X.509 certificate
// (saml_service.cert). Loaded with the private key to sign
// AuthnRequests and decrypt assertions; marked TODO for migration to
// configmap.
//
// SAML_KEY_FILE — Filesystem path to the SP's RSA private key
// (saml_service.key). Paired with SAML_CERT_FILE to form the SP
// keypair; marked TODO for migration to configmap.
//
// FLOWS
//
// See diagrams.md for sequence diagrams of: SP-initiated SSO login,
// IdP-initiated SSO login, and SAML single logout.
package saml
