// Package core provides the foundation types and interfaces for the OneAuth
// authentication framework. Every other OneAuth package imports core.
//
// The core package contains:
//   - User, Identity, and Channel types (the data model)
//   - Store interfaces (UserStore, IdentityStore, ChannelStore, etc.)
//   - Token types and token store interface
//   - Credentials, signup policies, and validation types
//   - Scope constants and helpers
//   - Email sender interface
//   - Request context helpers (GetUserIDFromContext, SetUserIDInContext)
package core
