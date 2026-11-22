package admin_test

// RFC 7591 §2: "The authorization server MUST ignore any client metadata
// sent by the client that it does not understand". An unknown field gets a
// normal registration, and the response, which echoes what was stored,
// leaves it out, so a client can see it didn't take (issue 557).
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDCR_UnknownMetadataIsIgnoredAndNotEchoed(t *testing.T) {
	r := jarmAlgRegistrar()
	code, resp := registerWith(t, r, `{"client_name":"u","redirect_uris":["https://rp.example/cb"],"grant_types":["authorization_code"],"made_up_field":"x","subjet_type":"pairwise"}`)
	require.Equal(t, http.StatusCreated, code, resp)
	assert.NotContains(t, resp, "made_up_field")
	assert.NotContains(t, resp, "subjet_type")
	assert.NotEqual(t, "pairwise", resp["subject_type"], "a misspelled field doesn't set the real one")
	assert.Equal(t, "u", storedApp(t, r, resp).ClientName)
}
