//go:build !wasm
// +build !wasm

// Package gorm provides GORM-based implementations of oneauth store interfaces.
// It supports any database that GORM supports (PostgreSQL, MySQL, SQLite, etc.)
// and is suitable for production deployments requiring relational database storage.
//
// # Database Schema
//
// The package auto-migrates the following tables:
//   - users: User accounts
//   - identities: Email/phone identities linked to users
//   - channels: Authentication channels (local, google, github, etc.)
//   - auth_tokens: Verification and password reset tokens
//   - refresh_tokens: Long-lived refresh tokens for API access
//   - api_keys: Long-lived API keys for programmatic access
//
// # Usage
//
//	db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
//	userStore := gormstore.NewUserStore(db)
//	refreshTokenStore := gormstore.NewRefreshTokenStore(db)
//	apiKeyStore := gormstore.NewAPIKeyStore(db)
package gorm
