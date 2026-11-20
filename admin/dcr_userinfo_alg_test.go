package admin_test

// userinfo_signed_response_alg in DCR (OIDC Registration §2, issue 485).
// A client that registers it gets userinfo as a signed JWT, so the AS
// accepts only an algorithm its userinfo endpoint can sign with.
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
)

const userinfoAlgClient = `{"client_name":"ui","redirect_uris":["https://rp.example/cb"],"grant_types":["authorization_code"],"userinfo_signed_response_alg":"%s"}`

func userinfoAlgRegistrar(algs ...string) *admin.AppRegistrar {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth())
	r.IssuerBaseURL = "http://example.com"
	r.UserinfoSigningAlgs = algs
	return r
}

func TestDCR_UserinfoSignedResponseAlgIsStoredAndEchoed(t *testing.T) {
	r := userinfoAlgRegistrar("RS256")
	code, resp := registerWith(t, r, sprintf(userinfoAlgClient, "RS256"))
	assert.Equal(t, http.StatusCreated, code, resp)
	assert.Equal(t, "RS256", resp["userinfo_signed_response_alg"])
	assert.Equal(t, "RS256", storedApp(t, r, resp).UserinfoSignedResponseAlg)
}

func TestDCR_UserinfoSignedResponseAlgTheASCannotSignWithIsRefused(t *testing.T) {
	code, resp := registerWith(t, userinfoAlgRegistrar("RS256"), sprintf(userinfoAlgClient, "ES256"))
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_client_metadata", resp["error"])

	code, resp = registerWith(t, userinfoAlgRegistrar(), sprintf(userinfoAlgClient, "RS256"))
	assert.Equal(t, http.StatusBadRequest, code, "no userinfo signing configured")
	assert.Equal(t, "invalid_client_metadata", resp["error"])
}

func sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }
