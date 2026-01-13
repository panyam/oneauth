# OneAuth Next Steps

## Completed (v0.2.0)

- [x] API Authentication (JWT access tokens, refresh tokens)
- [x] API Keys for long-lived programmatic access
- [x] Scope-based access control
- [x] APIMiddleware for endpoint protection
- [x] Token rotation with theft detection
- [x] GORM store implementations (SQL databases)
- [x] GAE/Datastore store implementations
- [x] Store reorganization into subdirectories
- [x] Comprehensive test coverage for API auth

## Short-term

### Phase 3: OAuth Integration for API
- [ ] Add API mode to OAuth callbacks (return tokens instead of session)
- [ ] Support token response for mobile OAuth flows
- [ ] PKCE support for public clients

### Phase 4: Client SDK
- [ ] Create `client/` package for token management
- [ ] Automatic token refresh
- [ ] Request interceptor for adding auth headers

### Improvements
- [ ] Rate limiting middleware (configurable)
- [ ] Audit logging interface
- [ ] Token blacklist for immediate JWT revocation
- [ ] Multi-tenancy support in core interfaces

## Medium-term

### Security Enhancements
- [ ] Multi-factor authentication (TOTP, WebAuthn)
- [ ] Account lockout after failed attempts
- [ ] Suspicious activity detection
- [ ] IP-based rate limiting

### Features
- [ ] Username-based login (currently email/phone only)
- [ ] Remember me tokens
- [ ] Account deletion and data export (GDPR)
- [ ] Social provider profile synchronization
- [ ] Password strength meter

### Infrastructure
- [ ] Redis store implementation for caching
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
2. **No built-in rate limiting**: Application must implement
3. **No CSRF protection**: Application must implement
4. **Console email sender only**: Production requires custom implementation

## Contributing

See CONTRIBUTING.md for guidelines. Priority areas:
- Documentation improvements
- Additional store implementations
- Security review and hardening
- Example applications
