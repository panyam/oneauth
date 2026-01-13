//go:build !wasm
// +build !wasm

// Package gae provides Google Cloud Datastore implementations of oneauth store interfaces.
// It is designed for deployment on Google Cloud Platform and supports multi-tenancy
// through Datastore namespaces.
//
// # Datastore Kinds
//
// The package uses the following Datastore kinds:
//   - User: User accounts with profile data
//   - Identity: Email/phone identities linked to users
//   - Channel: Authentication channels (local, google, github, etc.)
//   - AuthToken: Verification and password reset tokens
//   - RefreshToken: Long-lived refresh tokens for API access
//   - APIKey: Long-lived API keys for programmatic access
//
// # Namespacing
//
// All stores support Datastore namespaces for multi-tenant applications.
// Pass a namespace when creating stores to isolate data between tenants:
//
//	userStore := gae.NewUserStore(client, "tenant-123")
//	tokenStore := gae.NewRefreshTokenStore(client, "tenant-123")
//
// # Usage
//
//	client, _ := datastore.NewClient(ctx, projectID)
//	userStore := gae.NewUserStore(client, "")  // default namespace
//	refreshTokenStore := gae.NewRefreshTokenStore(client, "")
//	apiKeyStore := gae.NewAPIKeyStore(client, "")
package gae
