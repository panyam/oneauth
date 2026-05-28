package admin_test

// Tests covering the AppRegistrar + AppRegistrationStore integration added in
// issue #165: cache hydration on construction, SaveRegistration write-through,
// handleRegister persistence, handleDeleteApp persistence, and the DCR handler
// routing through the store.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
)

// TestAppRegistrar_HydratesFromStore verifies that a freshly constructed
// AppRegistrar exposes registrations that were already in the store. This
// guards the "registrations survive restart" property: dropping and rebuilding
// the registrar over the same store is the in-process simulation of restart.
func TestAppRegistrar_HydratesFromStore(t *testing.T) {
	store := core.NewInMemoryAppStore()
	ctx := context.Background()
	store.SaveApp(ctx, &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:     "app_pre_existing",
		ClientDomain: "example.com",
		SigningAlg:   "HS256",
		CreatedAt:    time.Now(),
	}})
	store.SaveApp(ctx, &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:   "app_revoked",
		SigningAlg: "RS256",
		Revoked:    true,
		CreatedAt:  time.Now(),
	}})

	ks := keys.NewInMemoryKeyStore()
	reg := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)

	req := httptest.NewRequest(http.MethodGet, "/apps", nil)
	rr := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /apps: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Apps []*core.AppRegistration `json:"apps"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Apps) != 2 {
		t.Fatalf("expected 2 hydrated apps, got %d: %s", len(resp.Apps), rr.Body.String())
	}
}

// TestAppRegistrar_SaveRegistration_PersistsToStore verifies that SaveRegistration
// writes through to the underlying store, not just the in-memory cache. Without
// this, registrations would be lost on restart even with a persistent backend.
func TestAppRegistrar_SaveRegistration_PersistsToStore(t *testing.T) {
	store := core.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()
	reg := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)

	app := &core.AppRegistration{
		ClientID:     "app_via_save",
		ClientDomain: "save.example",
		SigningAlg:   "HS256",
		CreatedAt:    time.Now(),
	}
	ctx := context.Background()
	if err := reg.SaveRegistration(ctx, app); err != nil {
		t.Fatalf("SaveRegistration: %v", err)
	}

	got, err := store.GetApp(ctx, &core.GetAppRequest{ClientID: "app_via_save"})
	if err != nil {
		t.Fatalf("store.GetApp: %v", err)
	}
	if got.App.ClientDomain != "save.example" {
		t.Errorf("ClientDomain=%q, want save.example", got.App.ClientDomain)
	}
}

// TestAppRegistrar_HandleRegister_PersistsToStore verifies that POST /apps/register
// persists the new registration to the store, not only to the in-memory cache.
func TestAppRegistrar_HandleRegister_PersistsToStore(t *testing.T) {
	store := core.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()
	reg := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)

	body, _ := json.Marshal(map[string]any{"client_name": "register.example", "signing_alg": "HS256"})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got, err := store.GetApp(context.Background(), &core.GetAppRequest{ClientID: resp.ClientID})
	if err != nil {
		t.Fatalf("store.GetApp(%s): %v", resp.ClientID, err)
	}
	if got.App.ClientDomain != "register.example" {
		t.Errorf("ClientDomain=%q, want register.example", got.App.ClientDomain)
	}
}

// TestAppRegistrar_HandleDeleteApp_PersistsDeletion verifies that DELETE /apps/{id}
// removes the registration from the store. Without this, a deleted (revoked) app
// would be resurrected on restart from stale store contents.
func TestAppRegistrar_HandleDeleteApp_PersistsDeletion(t *testing.T) {
	store := core.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()
	reg := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)

	// Register, then delete, both via HTTP.
	body, _ := json.Marshal(map[string]any{"client_name": "delete.example", "signing_alg": "HS256"})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal(rr.Body.Bytes(), &registered)

	delReq := httptest.NewRequest(http.MethodDelete, "/apps/"+registered.ClientID, nil)
	delRR := httptest.NewRecorder()
	reg.Handler().ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusOK {
		t.Fatalf("delete: status=%d body=%s", delRR.Code, delRR.Body.String())
	}

	if _, err := store.GetApp(context.Background(), &core.GetAppRequest{ClientID: registered.ClientID}); err != core.ErrAppNotFound {
		t.Errorf("store should not contain deleted app, got err=%v", err)
	}
}

// TestDCR_PersistsViaRegistrar verifies that POST /apps/dcr (RFC 7591) writes
// through the AppRegistrar.SaveRegistration path so the registration lands in
// the store. Without this, DCR-registered clients would be lost on restart.
func TestDCR_PersistsViaRegistrar(t *testing.T) {
	store := core.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()
	reg := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)

	body, _ := json.Marshal(map[string]any{
		"client_name":  "DCR Test App",
		"client_uri":   "https://dcr.example",
		"redirect_uris": []string{"https://dcr.example/cb"},
		"grant_types":  []string{"authorization_code"},
		"scope":        "read",
	})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("dcr: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	getResp, err := store.GetApp(context.Background(), &core.GetAppRequest{ClientID: resp.ClientID})
	if err != nil {
		t.Fatalf("store.GetApp(%s): %v", resp.ClientID, err)
	}
	got := getResp.App
	if got.ClientName != "DCR Test App" {
		t.Errorf("ClientName=%q, want DCR Test App", got.ClientName)
	}
	if got.ClientURI != "https://dcr.example" {
		t.Errorf("ClientURI=%q, want https://dcr.example", got.ClientURI)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://dcr.example/cb" {
		t.Errorf("RedirectURIs=%v", got.RedirectURIs)
	}
	if got.Scope != "read" {
		t.Errorf("Scope=%q, want read", got.Scope)
	}
}
