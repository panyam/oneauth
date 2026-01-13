# OneAuth Next Steps

## Completed (v0.2.0)

### Core Authentication
- [x] LocalAuth - browser-based login, signup, email verification, password reset
- [x] APIAuth - JWT access tokens, refresh tokens with rotation
- [x] API Keys for long-lived programmatic access
- [x] OAuth2 providers (Google, GitHub) with extensible base
- [x] Basic SAML support

### Security
- [x] Scope-based access control with role mapping
- [x] APIMiddleware for endpoint protection
- [x] Token rotation with theft detection (token family tracking)
- [x] Secure password hashing (bcrypt)
- [x] Cryptographically secure token generation

### Storage Backends
- [x] File-based stores (`stores/fs/`) - all 6 interfaces
- [x] GORM stores (`stores/gorm/`) - SQL databases with auto-migration
- [x] GAE/Datastore stores (`stores/gae/`) - Google Cloud

### Infrastructure
- [x] gRPC support - context utilities, auth interceptors
- [x] Session management - cookie and header-based
- [x] Comprehensive test coverage (~2,600 lines)

## Short-term

### Phase 3: OAuth Integration for API
- [ ] Add API mode to OAuth callbacks (return tokens instead of session)
- [ ] Support token response for mobile OAuth flows
- [ ] PKCE support for public clients

### Phase 4: Client SDK
Reference implementation: `lilbattle/cmd/cli/cmd/{credentials.go,login.go}` and `connectclient/worlds_client.go`

- [ ] Create `client/` package with stores pattern:
  - [ ] `CredentialStore` interface (Get, Set, Remove, List credentials)
  - [ ] `ServerCredential` struct (access token, refresh token, expiry, user info)
  - [ ] `client/stores/fs/` - FS-based credential store (`~/.config/<app>/credentials.json`)
  - [ ] Future: `client/stores/gorm/`, `client/stores/gae/`
- [ ] `AuthTransport` - `http.RoundTripper` that injects Bearer headers
- [ ] `NewHTTPClient(serverURL, store)` - creates authenticated HTTP client
- [ ] Automatic token refresh:
  - [ ] Store refresh tokens alongside access tokens
  - [ ] Transparent refresh on 401 or before expiry
  - [ ] `grant_type=refresh_token` support
- [ ] Migrate lilbattle CLI to use oneauth/client package

### Phase 5: Model Generation with protoc-gen-dal
Reference: `lilbattle/protos/lilbattle/v1/gorm/models.proto` and `gae/` subfolder

Currently each store implementation redeclares model types (FSUser, GORMUser, GAEUser, etc.). Use protoc-gen-dal to generate database-specific models from a single proto definition.

- [ ] Create `protos/oneauth/v1/models.proto` with core types (User, Identity, Channel, Token, etc.)
- [ ] Create `protos/oneauth/v1/gorm/models.proto` with GORM annotations
- [ ] Create `protos/oneauth/v1/gae/models.proto` with Datastore annotations
- [ ] Generate models with `buf generate`
- [ ] Refactor `stores/fs/` to use generated types
- [ ] Refactor `stores/gorm/` to use generated GORM models
- [ ] Refactor `stores/gae/` to use generated GAE models
- [ ] Remove hand-written model types from store implementations

### Improvements
- [ ] Token blacklist for immediate JWT revocation
- [ ] Audit logging with default implementations
- [ ] Username-based login (currently email/phone only)

## Medium-term

### Security Enhancements
- [ ] Multi-factor authentication (TOTP, WebAuthn)
- [ ] Account lockout after failed attempts
- [ ] Suspicious activity detection
- [ ] IP-based rate limiting (beyond current interface)

### Features
- [ ] Remember me tokens (extended session cookies)
- [ ] Account deletion and data export (GDPR)
- [ ] Social provider profile synchronization
- [ ] Password strength validation
- [ ] Token introspection endpoint

### Infrastructure
- [ ] Redis store implementation for caching/distributed deployments
- [ ] MongoDB store implementation
- [ ] Metrics and observability hooks
- [ ] OpenTelemetry integration

## Long-term

### Advanced Features
- [ ] Organization/team support
- [ ] Role-based access control (RBAC)
- [ ] Custom claims in JWT
- [ ] Token introspection endpoint
- [ ] Device management UI components

### Ecosystem
- [ ] Example applications
- [ ] Admin dashboard package
- [ ] React/Vue component library for auth UI
- [ ] CLI tool for token management

## Known Limitations

1. **File-based stores**: Not suitable for >1000 users or clustered deployments
2. **Rate limiting interface only**: Provides interface, application implements logic
3. **No CSRF protection**: Application must implement
4. **Console email sender only**: Production requires custom EmailSender implementation
5. **No MFA yet**: TOTP/WebAuthn planned for medium-term

## Contributing

See CONTRIBUTING.md for guidelines. Priority areas:
- Documentation improvements
- Additional store implementations
- Security review and hardening
- Example applications
