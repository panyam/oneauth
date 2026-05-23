// Package grpc provides authentication context utilities and server
// interceptors for propagating the authenticated user ID across the
// HTTP-to-gRPC boundary via gRPC metadata, with optional auth enforcement
// and switch-user impersonation.
//
// This package owns the small surface that carries identity between an
// HTTP edge (or any gRPC client) and downstream gRPC services. Identity
// travels as gRPC metadata: a configurable user-ID key (default
// "x-user-id") and an optional switch-user key (default "x-switch-user")
// for impersonation. It owns extraction helpers, outgoing-metadata
// injectors, and unary/stream server interceptors that optionally reject
// unauthenticated calls. It does NOT verify credentials, mint or
// validate tokens, or resolve users — it only moves an already-established
// user ID around. Notable: the interceptors enforce presence of a user ID
// but never write the ID into the context, so handlers still call
// UserIDFromContext to read it; switch-user is honored only when the
// server enables it, so a client cannot self-grant impersonation.
//
// ENTITIES
//
// DefaultMetadataKeyUserID — default metadata key "x-user-id" for the
// user ID. Lowercase per gRPC metadata-key normalization rules.
//
// DefaultMetadataKeySwitchUser — default metadata key "x-switch-user"
// for impersonation; honored only when switch auth is enabled.
//
// Config — metadata-key names plus the EnableSwitchAuth toggle used by
// extraction. Keys are customizable to avoid collisions with other
// metadata.
//
// DefaultConfig — returns a Config with default keys and switch-auth
// disabled. Safe default — impersonation is off unless opted into.
//
// Config.EnsureDefaults — fills any empty key fields with their defaults
// in place, so partially populated configs are safe.
//
// UserIDFromContext — extracts the user ID from incoming metadata using
// defaults; returns "" for anonymous requests so callers decide how to
// treat them.
//
// UserIDFromContextWithConfig — same extraction with a supplied Config;
// checks the switch-user key before the real user ID when
// EnableSwitchAuth is on.
//
// UserIDToOutgoingContext — appends the user ID to outgoing metadata
// (default key), used to forward identity into downstream gRPC calls.
//
// UserIDToOutgoingContextWithKey — outgoing user-ID append with a
// custom key, mirroring the configurable key on the extraction side.
//
// SwitchUserToOutgoingContext — appends a switch-user header (default
// key); no effect unless the server enables switch auth, so a client
// cannot self-grant.
//
// SwitchUserToOutgoingContextWithKey — switch-user append with a custom
// key, pairing with the custom-key extraction path.
//
// IsAuthenticated — true when the context carries a non-empty user ID;
// convenience predicate over UserIDFromContext.
//
// IsAuthenticatedWithConfig — authentication predicate with an explicit
// Config so switch-user-aware callers test presence consistently with
// extraction.
//
// InterceptorConfig — embeds Config and adds RequireAuth plus a
// PublicMethods bypass set keyed by full "/pkg.Service/Method" names
// matched against grpc info.FullMethod.
//
// DefaultInterceptorConfig — requires auth on every method, no public
// bypass; secure-by-default posture for new servers.
//
// NewPublicMethodsConfig — require-auth config seeded with the given
// public (unauthenticated) methods; common case for health/login.
//
// OptionalAuthConfig — config that lets unauthenticated requests
// through; for services that read identity opportunistically.
//
// UnaryAuthInterceptor — unary server interceptor that rejects with
// codes.Unauthenticated only when RequireAuth is set and the method is
// not public; it does not inject identity into the context, leaving
// downstream extraction to UserIDFromContext.
//
// StreamAuthInterceptor — stream counterpart enforcing the same
// per-method rules once at stream open against ss.Context(); per-message
// identity is unchanged.
//
// FLOWS
//
// See diagrams.md for sequence diagrams of: interceptor auth enforcement
// and public-method bypass; HTTP-to-gRPC context propagation.
package grpc
