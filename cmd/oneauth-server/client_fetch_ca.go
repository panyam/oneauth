package main

import (
	"crypto/x509"
	"fmt"
	"os"
)

// clientFetchRootCAs returns the CAs oneauth-server trusts when it fetches
// a client's jwks_uri: the system roots plus the certificates in path
// (admin_auth.client_fetch_ca_file). Empty path returns nil, which keeps
// the system roots. A missing file, or one with no certificate, is an
// error, so a typo stops the server instead of silently trusting less.
func clientFetchRootCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("admin_auth.client_fetch_ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("admin_auth.client_fetch_ca_file %s holds no PEM certificate", path)
	}
	return pool, nil
}
