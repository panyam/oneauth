# OneAuth Project Audit

**Date:** January 2026
**Version Analyzed:** v0.2.0
**Branch:** claude/project-audit-Q73eR

## Executive Summary

OneAuth is a well-designed Go authentication library with comprehensive features including browser-based auth, API auth (JWT/refresh tokens/API keys), OAuth2, and multiple storage backends. The codebase is clean and well-documented, but there are several gaps in CI/CD, testing, and infrastructure that should be addressed.

---

## 1. Critical Issues

### 1.1 Missing CI/CD Pipeline
**Priority: HIGH**

- No `.github/workflows/` directory exists
- No automated testing, linting, or build verification on PRs
- No automated release process

**Recommended Actions:**
- [ ] Add GitHub Actions workflow for testing (`go test ./...`)
- [ ] Add linting workflow with golangci-lint
- [ ] Add workflow for PR checks (build, test, lint)
- [ ] Add release automation for tagged versions

### 1.2 Test Coverage Gaps
**Priority: HIGH**

Current coverage by package:
| Package | Coverage | Status |
|---------|----------|--------|
| `oneauth` (main) | 52.8% | Needs improvement |
| `client` | 73.1% | Good |
| `client/stores/fs` | 77.9% | Good |
| `grpc` | 95.2% | Excellent |
| `oauth2` | 94.9% | Excellent |
| `saml` | 0.0% | **No tests** |
| `stores/fs` | 0.0% | **No tests** |
| `stores/gorm` | 0.0% | **No tests** |
| `stores/gae` | N/A | Build failure (dependencies) |

**Recommended Actions:**
- [ ] Add unit tests for `stores/fs/` package
- [ ] Add unit tests for `stores/gorm/` package
- [ ] Add tests or remove `saml/` package if not implemented
- [ ] Increase main package coverage to >70%

### 1.3 GAE Store Build Issues
**Priority: MEDIUM**

The `stores/gae` package fails to build due to dependency resolution issues:
```
google.golang.org/api@v0.259.0: dial tcp: lookup storage.googleapis.com...
```

**Recommended Actions:**
- [ ] Pin GAE dependency versions for offline builds
- [ ] Add build tags to exclude GAE in non-GCP environments
- [ ] Consider making GAE store a separate module

---

## 2. Missing Infrastructure

### 2.1 No Linting Configuration
**Priority: MEDIUM**

No `.golangci.yml` or equivalent linting configuration.

**Recommended Actions:**
- [ ] Add `.golangci.yml` with standard Go linting rules
- [ ] Configure linters: `gofmt`, `govet`, `errcheck`, `staticcheck`, `gosec`
- [ ] Add pre-commit hooks for local linting

### 2.2 Minimal Makefile
**Priority: LOW**

Current Makefile only contains:
```makefile
test:
	go test -v ./...
```

**Recommended Actions:**
- [ ] Add `lint` target
- [ ] Add `build` target
- [ ] Add `cover` target (with HTML report)
- [ ] Add `clean` target
- [ ] Add `fmt` target
- [ ] Add `generate` target (for future proto generation)

### 2.3 Missing CONTRIBUTING.md
**Priority: MEDIUM**

The `NEXTSTEPS.md` references `CONTRIBUTING.md` but this file doesn't exist.

**Recommended Actions:**
- [ ] Create `CONTRIBUTING.md` with:
  - Development setup instructions
  - Code style guidelines
  - PR process
  - Issue reporting guidelines
  - Testing requirements

---

## 3. Documentation Inconsistencies

### 3.1 NEXTSTEPS.md Outdated
**Priority: LOW**

Phase 4 (Client SDK) items are shown as incomplete but the implementation exists:
- `client/` package with `AuthClient` ✓
- `CredentialStore` interface ✓
- `client/stores/fs/` implementation ✓
- `AuthTransport` ✓
- Automatic token refresh ✓

**Recommended Actions:**
- [ ] Update NEXTSTEPS.md to mark Phase 4 as complete
- [ ] Update version to reflect Client SDK completion

---

## 4. Security Considerations

### 4.1 Known Limitations (Already Documented)

These are acknowledged in documentation but worth tracking:
- [ ] No CSRF protection (app must implement)
- [ ] Rate limiting interface only (no default implementation)
- [ ] No MFA support yet (planned medium-term)
- [ ] Console email sender only (production needs custom)

### 4.2 Recommended Security Additions

- [ ] Add security policy (`SECURITY.md`) for vulnerability reporting
- [ ] Run `gosec` in CI pipeline
- [ ] Consider adding Dependabot/Renovate for dependency updates
- [ ] Add example CSRF middleware in documentation

---

## 5. Code Quality

### 5.1 Strengths
- Clean three-layer architecture (User → Identity → Channel)
- Well-defined interfaces for all stores
- Comprehensive package documentation (`doc.go`)
- Good separation of concerns
- Framework-agnostic design
- Security-first approach (bcrypt, JWT, secure tokens)

### 5.2 Improvements Needed

- [ ] Add godoc comments to exported types in `stores/` packages
- [ ] Consider adding interface assertions (compile-time checks)
- [ ] Add more inline code comments in complex logic (api_auth.go:700+ lines)

---

## 6. Feature Gaps (from NEXTSTEPS.md)

### Short-term (High Value)
- [ ] OAuth API mode (return tokens instead of session)
- [ ] PKCE support for public/mobile clients
- [ ] Username-based login (currently email/phone only)
- [ ] Token blacklist for immediate JWT revocation

### Medium-term
- [ ] Multi-factor authentication (TOTP, WebAuthn)
- [ ] Account lockout after failed attempts
- [ ] Remember me tokens
- [ ] GDPR compliance (account deletion, data export)
- [ ] Password strength validation

### Long-term
- [ ] Organization/team support
- [ ] RBAC (Role-based access control)
- [ ] Redis/MongoDB store implementations
- [ ] OpenTelemetry integration
- [ ] Admin dashboard

---

## 7. Recommended Immediate Actions

### Week 1: CI/CD & Testing Foundation
1. Create `.github/workflows/ci.yml` with test and lint jobs
2. Add `.golangci.yml` configuration
3. Create `CONTRIBUTING.md`
4. Fix NEXTSTEPS.md Phase 4 status

### Week 2: Test Coverage
1. Add tests for `stores/fs/` package
2. Add tests for `stores/gorm/` package
3. Improve main package coverage to >70%

### Week 3: Build & Security
1. Fix GAE build issues (build tags or module split)
2. Add `SECURITY.md`
3. Expand Makefile targets
4. Set up Dependabot

---

## 8. Metrics Summary

| Metric | Value |
|--------|-------|
| Total Go files | 45 |
| Total lines of code | ~10,900 |
| Test files | 9 |
| Test lines | ~2,600 |
| Documentation files | 7 |
| Average test coverage | ~49% (excluding failing packages) |
| Store implementations | 3 (fs, gorm, gae) |
| OAuth providers | 2 (Google, GitHub) |

---

## 9. Conclusion

OneAuth is a solid authentication library with a well-thought-out architecture. The main gaps are in **DevOps infrastructure** (CI/CD, linting) and **test coverage** for storage implementations. Addressing these issues will significantly improve maintainability and contribution friendliness.

The codebase is production-ready for the features it supports, but adding CI/CD should be the top priority before additional features are developed.
