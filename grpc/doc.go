// Package grpc provides authentication context utilities and server
// interceptors for propagating the authenticated user ID across the
// HTTP-to-gRPC boundary via gRPC metadata, with optional auth enforcement
// and switch-user impersonation.
//
// <!-- design:start -->
// This package owns the small surface that carries identity between an HTTP
// edge (or any gRPC client) and downstream gRPC services. Identity travels as
// gRPC metadata: a configurable user-ID key (default "x-user-id") and an
// optional switch-user key (default "x-switch-user") for impersonation. It
// owns extraction helpers, outgoing-metadata injectors, and unary/stream
// server interceptors that optionally reject unauthenticated calls. It does
// NOT verify credentials, mint or validate tokens, or resolve users — it only
// moves an already-established user ID around. Notable: the interceptors
// enforce presence of a user ID but never write the ID into the context, so
// handlers still call UserIDFromContext to read it; switch-user is honored
// only when the server enables it, so a client cannot self-grant impersonation.
//
// # ENTITIES
//
// DefaultMetadataKeyUserID — default metadata key "x-user-id" for the user ID.
//
// DefaultMetadataKeySwitchUser — default metadata key "x-switch-user" for
// impersonation; honored only when switch auth is enabled.
//
// Config — metadata-key names plus the EnableSwitchAuth toggle used by
// extraction.
//
// DefaultConfig — Config with default keys and switch-auth disabled.
//
// Config.EnsureDefaults — fills any empty key fields with their defaults in
// place, so partially populated configs are safe.
//
// UserIDFromContext — extracts the user ID from incoming metadata using
// defaults; returns "" for anonymous requests.
//
// UserIDFromContextWithConfig — same extraction with a supplied Config; checks
// the switch-user key before the real user ID when EnableSwitchAuth is on.
//
// UserIDToOutgoingContext — appends the user ID to outgoing metadata (default
// key), used to forward identity into downstream gRPC calls.
//
// UserIDToOutgoingContextWithKey — outgoing user-ID append with a custom key.
//
// SwitchUserToOutgoingContext — appends a switch-user header (default key);
// no effect unless the server enables switch auth.
//
// SwitchUserToOutgoingContextWithKey — switch-user append with a custom key.
//
// IsAuthenticated — true when the context carries a non-empty user ID.
//
// IsAuthenticatedWithConfig — authentication predicate with an explicit Config.
//
// InterceptorConfig — embeds Config and adds RequireAuth plus a PublicMethods
// bypass set keyed by full "/pkg.Service/Method" names.
//
// DefaultInterceptorConfig — requires auth on every method, no public bypass.
//
// NewPublicMethodsConfig — require-auth config seeded with the given public
// (unauthenticated) methods.
//
// OptionalAuthConfig — config that lets unauthenticated requests through.
//
// UnaryAuthInterceptor — unary server interceptor that rejects with
// Unauthenticated only when RequireAuth is set and the method is not public;
// it does not inject identity into the context.
//
// StreamAuthInterceptor — stream counterpart enforcing the same per-method
// rules once at stream open against ss.Context().
//
// # FLOWS
//
// See diagrams.md for the interceptor auth-enforcement / public-method bypass
// flow and the HTTP-to-gRPC context propagation flow.
// <!-- design:end -->
package grpc
