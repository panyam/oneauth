package admin_test

// subject_type and sector_identifier_uri in DCR (OIDC Core §8.1, OIDC
// Registration §2 and §5, issue 507). Registration settles the sector a
// pairwise sub is derived from: the sector_identifier_uri's host, whose
// document must list every redirect URI, or the redirect URIs' one host.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation
// See: https://github.com/panyam/oneauth/issues/507

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

const sectorURI = "https://sector.example/redirects.json"

// pairwiseRegistrar has pairwise on, and serves sectorDoc for sectorURI.
func pairwiseRegistrar(sectorDoc []string) *admin.AppRegistrar {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())
	r.IssuerBaseURL = "http://example.com"
	r.PairwiseSubjects = true
	r.FetchSectorIdentifier = func(_ context.Context, uri string) ([]string, error) {
		if uri != sectorURI {
			return nil, errors.New("unreachable")
		}
		return sectorDoc, nil
	}
	return r
}

func registerWith(t *testing.T, r *admin.AppRegistrar, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, req)
	resp := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	return rr.Code, resp
}

func storedApp(t *testing.T, r *admin.AppRegistrar, resp map[string]any) *core.AppRegistration {
	t.Helper()
	got, err := r.Store.GetApp(context.Background(), &core.GetAppRequest{ClientID: resp["client_id"].(string)})
	require.NoError(t, err)
	return got.App
}

// Without a sector_identifier_uri the sector is the redirect URIs' host.
func TestDCR_PairwiseSectorFromRedirectHost(t *testing.T) {
	r := pairwiseRegistrar(nil)
	code, resp := registerWith(t, r, `{"redirect_uris":["https://app.example/a","https://app.example/b"],"subject_type":"pairwise"}`)
	require.Equal(t, http.StatusCreated, code, resp)
	assert.Equal(t, "pairwise", resp["subject_type"])
	app := storedApp(t, r, resp)
	assert.Equal(t, "pairwise", app.SubjectType)
	assert.Equal(t, "app.example", app.SectorIdentifier)
}

// See: https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
func TestDCR_PairwiseSectorFromSectorIdentifierURI(t *testing.T) {
	r := pairwiseRegistrar([]string{"https://a.example/cb", "https://b.example/cb", "https://c.example/cb"})
	code, resp := registerWith(t, r, `{"redirect_uris":["https://a.example/cb","https://b.example/cb"],"subject_type":"pairwise","sector_identifier_uri":"`+sectorURI+`"}`)
	require.Equal(t, http.StatusCreated, code, resp)
	assert.Equal(t, sectorURI, resp["sector_identifier_uri"])
	app := storedApp(t, r, resp)
	assert.Equal(t, "sector.example", app.SectorIdentifier)
	assert.Equal(t, sectorURI, app.SectorIdentifierURI)
}

func TestDCR_PairwiseRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		r    *admin.AppRegistrar
		body string
	}{
		"pairwise off": {admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth()),
			`{"redirect_uris":["https://app.example/cb"],"subject_type":"pairwise"}`},
		"unknown subject_type": {pairwiseRegistrar(nil),
			`{"redirect_uris":["https://app.example/cb"],"subject_type":"secret"}`},
		"two hosts, no sector URI": {pairwiseRegistrar(nil),
			`{"redirect_uris":["https://a.example/cb","https://b.example/cb"],"subject_type":"pairwise"}`},
		"redirect URI missing from the sector document": {pairwiseRegistrar([]string{"https://a.example/cb"}),
			`{"redirect_uris":["https://a.example/cb","https://b.example/cb"],"subject_type":"pairwise","sector_identifier_uri":"` + sectorURI + `"}`},
		"sector URI not https": {func() *admin.AppRegistrar {
			r := pairwiseRegistrar(nil)
			r.FetchSectorIdentifier = func(context.Context, string) ([]string, error) { return []string{"https://app.example/cb"}, nil }
			return r
		}(),
			`{"redirect_uris":["https://app.example/cb"],"subject_type":"pairwise","sector_identifier_uri":"http://sector.example/r.json"}`},
		"sector document unreachable": {pairwiseRegistrar(nil),
			`{"redirect_uris":["https://app.example/cb"],"subject_type":"pairwise","sector_identifier_uri":"https://down.example/r.json"}`},
		"sector URI with no fetcher": {func() *admin.AppRegistrar {
			r := pairwiseRegistrar(nil)
			r.FetchSectorIdentifier = nil
			return r
		}(), `{"redirect_uris":["https://app.example/cb"],"subject_type":"pairwise","sector_identifier_uri":"` + sectorURI + `"}`},
	} {
		tc.r.IssuerBaseURL = "http://example.com"
		code, resp := registerWith(t, tc.r, tc.body)
		assert.Equal(t, http.StatusBadRequest, code, name)
		assert.Equal(t, "invalid_client_metadata", resp["error"], name)
	}
}

// A public client may name a sector_identifier_uri too; its document is
// still checked against the redirect URIs.
func TestDCR_PublicClientSectorURIIsStillChecked(t *testing.T) {
	r := pairwiseRegistrar([]string{"https://a.example/cb"})
	code, _ := registerWith(t, r, `{"redirect_uris":["https://b.example/cb"],"sector_identifier_uri":"`+sectorURI+`"}`)
	assert.Equal(t, http.StatusBadRequest, code)
}

// The sector fixes every pairwise sub the client's users have, so an
// update can't change the subject type or the sector.
func TestDCR_UpdateKeepsTheSector(t *testing.T) {
	r := pairwiseRegistrar([]string{"https://app.example/cb", "https://other.example/cb"})
	code, resp := registerWith(t, r, `{"redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"subject_type":"pairwise"}`)
	require.Equal(t, http.StatusCreated, code, resp)
	id, tok := resp["client_id"].(string), resp["registration_access_token"].(string)
	update := func(md *admin.DCRRequest) error {
		md.GrantTypes = []string{"authorization_code"}
		_, err := r.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{ClientID: id, AccessToken: tok, Metadata: md})
		return err
	}
	assert.ErrorIs(t, update(&admin.DCRRequest{RedirectURIs: []string{"https://app.example/cb"}, SubjectType: "public"}), admin.ErrInvalidClientMetadata)
	assert.ErrorIs(t, update(&admin.DCRRequest{RedirectURIs: []string{"https://other.example/cb"}}), admin.ErrInvalidClientMetadata,
		"a redirect URI on another host would leave the sector")
	assert.ErrorIs(t, update(&admin.DCRRequest{RedirectURIs: []string{"https://app.example/cb"}, SectorIdentifierURI: sectorURI}), admin.ErrInvalidClientMetadata)
	assert.Equal(t, "app.example", storedApp(t, r, resp).SectorIdentifier)
}

// A client with a sector_identifier_uri keeps every redirect URI in that
// document, on update as on registration.
func TestDCR_UpdateChecksTheSectorDocument(t *testing.T) {
	r := pairwiseRegistrar([]string{"https://a.example/cb", "https://b.example/cb"})
	code, resp := registerWith(t, r, `{"redirect_uris":["https://a.example/cb"],"grant_types":["authorization_code"],"subject_type":"pairwise","sector_identifier_uri":"`+sectorURI+`"}`)
	require.Equal(t, http.StatusCreated, code, resp)
	id, tok := resp["client_id"].(string), resp["registration_access_token"].(string)
	update := func(uris ...string) error {
		out, err := r.UpdateRegistration(context.Background(), &admin.UpdateRegistrationRequest{ClientID: id, AccessToken: tok,
			Metadata: &admin.DCRRequest{RedirectURIs: uris, GrantTypes: []string{"authorization_code"}}})
		if err == nil {
			tok = out.Registration.RegistrationAccessToken
		}
		return err
	}
	assert.NoError(t, update("https://a.example/cb", "https://b.example/cb"))
	assert.ErrorIs(t, update("https://c.example/cb"), admin.ErrInvalidClientMetadata)
}
