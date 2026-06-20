package apiauth_test

// Shared test fixtures for the apiauth package. Centralizes the
// OneAuth + per-handler wire-up so individual test files don't have
// to repeat the boilerplate. Migrated from the per-test setup
// functions when APIAuth was retired (#298).

import (
	"net/http"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

// apiAuthFixture bundles the OneAuth instance + the HTTP handlers
// that replaced the legacy APIAuth god struct, plus the JWT signing
// secret/issuer for APIMiddleware fixtures and the underlying stores
// for assertions on the post-condition state.
type apiAuthFixture struct {
	OneAuth       *apiauth.OneAuth
	TokenEndpoint *apiauth.TokenEndpointHandler
	Sessions      *apiauth.SessionsHandler
	APIKeys       *apiauth.APIKeysHandler
	JWTSecret     string
	JWTIssuer     string
	JWTAudience   string
}

// ServeHTTP routes to the TokenEndpointHandler — the most common
// call site in legacy tests that wired apiAuth.ServeHTTP into
// httptest.NewServer / handlers.
func (f *apiAuthFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.TokenEndpoint.ServeHTTP(w, r)
}

// HandleLogout / HandleLogoutAll / HandleListSessions delegate to the
// SessionsHandler.
func (f *apiAuthFixture) HandleLogout(w http.ResponseWriter, r *http.Request) {
	f.Sessions.HandleLogout(w, r)
}
func (f *apiAuthFixture) HandleLogoutAll(w http.ResponseWriter, r *http.Request) {
	f.Sessions.HandleLogoutAll(w, r)
}
func (f *apiAuthFixture) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	f.Sessions.HandleListSessions(w, r)
}

// HandleAPIKeys / HandleRevokeAPIKey delegate to the APIKeysHandler.
func (f *apiAuthFixture) HandleAPIKeys(w http.ResponseWriter, r *http.Request) {
	f.APIKeys.HandleAPIKeys(w, r)
}
func (f *apiAuthFixture) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	f.APIKeys.HandleRevokeAPIKey(w, r)
}

// Validator returns the OneAuth validator for tests that round-trip
// access tokens directly.
func (f *apiAuthFixture) Validator() apiauth.TokenValidator {
	return f.OneAuth.Validator
}

// Issuer returns the OneAuth token issuer.
func (f *apiAuthFixture) Issuer() apiauth.TokenIssuer {
	return f.OneAuth.Issuer
}

// RefreshTokenStore exposes the OneAuth refresh-token store so
// fixture callers can run direct assertions (revoke checks,
// theft-detection state, etc).
func (f *apiAuthFixture) RefreshTokenStore() core.RefreshTokenStore {
	return f.OneAuth.RefreshStore
}

// DeviceAuthStore is the device-authorization store shortcut for
// tests that read/write directly.
func (f *apiAuthFixture) DeviceAuthStore() core.DeviceAuthorizationStore {
	return f.OneAuth.DeviceAuthStore
}

// ApproveDeviceAuthorization wraps the device store's approve so
// device-flow tests can drive the user-consent step without going
// through the verification HTML UI. Mirrors the legacy
// APIAuth.ApproveDeviceAuthorization signature.
func (f *apiAuthFixture) ApproveDeviceAuthorization(r *http.Request, userCode, subject string, scopes []string) error {
	store := f.OneAuth.DeviceAuthStore
	if store == nil {
		return nil
	}
	_, err := store.ApproveDeviceAuthorization(r.Context(), &core.ApproveDeviceAuthorizationRequest{
		UserCode:        userCode,
		ApprovedSubject: subject,
		GrantedScopes:   scopes,
	})
	return err
}

// DenyDeviceAuthorization is the deny counterpart of
// ApproveDeviceAuthorization.
func (f *apiAuthFixture) DenyDeviceAuthorization(r *http.Request, userCode string) error {
	store := f.OneAuth.DeviceAuthStore
	if store == nil {
		return nil
	}
	_, err := store.DenyDeviceAuthorization(r.Context(), &core.DenyDeviceAuthorizationRequest{UserCode: userCode})
	return err
}

// newAPIAuthFixture wires a OneAuth-backed fixture with the supplied
// config. Convenience for tests that don't need every field on
// OneAuthConfig.
//
// When cfg.ValidateCredentials is non-nil the helper also wires
// OneAuth.PasswordGranter — many existing tests POST
// grant_type=password and rely on ROPC being implicit. Post-#294 the
// granter is opt-in in production; the test helper auto-opts when the
// caller signals intent by supplying the credentials validator.
// Callers that explicitly need the strict-2.1 default (granter nil)
// can clear oa.PasswordGranter after construction.
func newAPIAuthFixture(cfg apiauth.OneAuthConfig, apiKeyStore core.APIKeyStore) *apiAuthFixture {
	if cfg.SigningAlg == "" {
		cfg.SigningAlg = "HS256"
	}
	oa := apiauth.NewOneAuth(cfg)
	if cfg.ValidateCredentials != nil {
		oa.PasswordGranter = apiauth.NewPasswordGranter(apiauth.PasswordGranterConfig{
			Issuer:              oa.Issuer,
			ValidateCredentials: cfg.ValidateCredentials,
			GetSubjectScopes:    cfg.GetSubjectScopes,
		})
	}
	fx := &apiAuthFixture{
		OneAuth:       oa,
		TokenEndpoint: apiauth.NewTokenEndpointHandler(oa),
		Sessions:      oa.SessionsHTTPHandler(),
		JWTIssuer:     cfg.Issuer,
		JWTAudience:   cfg.Audience,
	}
	if b, ok := cfg.SigningKey.([]byte); ok {
		fx.JWTSecret = string(b)
	}
	if apiKeyStore != nil {
		fx.APIKeys = oa.APIKeysHTTPHandler(apiKeyStore, cfg.GetSubjectScopes)
	}
	return fx
}
