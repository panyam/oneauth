package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// admin_auth.client_fetch_ca_file adds a CA for fetching clients' jwks_uri
// (issue 507), so the OIDF harness's self-signed certificate is trusted.
func TestClientFetchRootCAs(t *testing.T) {
	pool, err := clientFetchRootCAs("")
	require.NoError(t, err)
	assert.Nil(t, pool, "unset keeps the system roots")

	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	pool, err = clientFetchRootCAs(path)
	require.NoError(t, err)
	_, err = srv.Certificate().Verify(x509.VerifyOptions{Roots: pool})
	assert.NoError(t, err)

	_, err = clientFetchRootCAs(filepath.Join(t.TempDir(), "missing.pem"))
	assert.Error(t, err)
	empty := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(empty, []byte("not a cert"), 0o600))
	_, err = clientFetchRootCAs(empty)
	assert.Error(t, err, "a file with no certificate is a misconfiguration")
}
