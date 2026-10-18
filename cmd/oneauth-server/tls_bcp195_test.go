package main

// When the server terminates TLS itself it follows BCP 195: TLS 1.2 or
// later, and on TLS 1.2 only ECDHE with AES-GCM.
//
// See: https://www.rfc-editor.org/rfc/rfc9325#section-4.2
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.2.1
// See: https://github.com/panyam/oneauth/issues/440

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLS_TLS12AcceptsOnlyBCP195Suites(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for name, key := range map[string]crypto.Signer{"RSA": rsaKey, "ECDSA": ecKey} {
		t.Run(name, func(t *testing.T) {
			addr := startTLSServer(t, key)

			for _, s := range tls.CipherSuites() {
				if !supportsTLS12(s) || !suiteFitsKey(s.Name, name) {
					continue
				}
				err := handshake(addr, tls.VersionTLS12, tls.VersionTLS12, s.ID)
				if slices.Contains(bcp195CipherSuites, s.ID) {
					assert.NoError(t, err, "%s is BCP 195", s.Name)
				} else {
					assert.Error(t, err, "%s is not BCP 195", s.Name)
				}
			}
			for _, s := range tls.InsecureCipherSuites() {
				if supportsTLS12(s) && suiteFitsKey(s.Name, name) {
					assert.Error(t, handshake(addr, tls.VersionTLS12, tls.VersionTLS12, s.ID), s.Name)
				}
			}
			assert.NoError(t, handshake(addr, tls.VersionTLS13, tls.VersionTLS13, 0), "TLS 1.3")
			assert.Error(t, handshake(addr, tls.VersionTLS11, tls.VersionTLS11, 0), "TLS 1.1")
		})
	}
}

func startTLSServer(t *testing.T, key crypto.Signer) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = serverTLSConfig()
	srv.TLS.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func handshake(addr string, minV, maxV, suite uint16) error {
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: minV, MaxVersion: maxV}
	if suite != 0 {
		cfg.CipherSuites = []uint16{suite}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}

func supportsTLS12(s *tls.CipherSuite) bool {
	return slices.Contains(s.SupportedVersions, tls.VersionTLS12)
}

// suiteFitsKey reports whether a suite can be negotiated with a certificate
// of this key type: ECDHE_ECDSA needs an ECDSA key, ECDHE_RSA and plain RSA
// key exchange an RSA one.
func suiteFitsKey(suite, keyType string) bool {
	if keyType == "ECDSA" {
		return strings.Contains(suite, "_ECDSA_")
	}
	return !strings.Contains(suite, "_ECDSA_")
}
