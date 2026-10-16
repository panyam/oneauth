package apiauth_test

// A resource server may trust several authorization servers (RFC 9728 §2
// authorization_servers is a list). Mounting the metadata proxy for more
// than one used to register the same pattern twice, which panics.
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-2
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panyam/oneauth/apiauth"
)

func TestProtectedResource_SeveralAuthorizationServers(t *testing.T) {
	mux := http.NewServeMux()
	meta := &apiauth.ProtectedResourceMetadata{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://idp.example.com/realms/a", "https://idp.example.com/realms/b", "https://other-idp.example.com/realms/a"},
	}
	assert.NotPanics(t, func() { apiauth.MountProtectedResource(mux, meta, true) })
}
