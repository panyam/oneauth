package asflow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// ClientMetadataDocument is the client ID metadata document for a public
// PKCE client at docURL, with the framework's callback as its one redirect
// URI (draft-ietf-oauth-client-id-metadata-document-03, issue 532). It has
// what MCP requires, client_id, client_name and redirect_uris, and leaves
// token_endpoint_auth_method out, which means none.
func ClientMetadataDocument(docURL, redirectURI string) map[string]any {
	return map[string]any{
		"client_id":      docURL,
		"client_name":    "MCP conformance (client ID metadata document)",
		"redirect_uris":  []string{redirectURI},
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scope":          "read",
	}
}

// ServeClientMetadata serves doc over TLS on addr at the path of its
// client_id, with certFile and keyFile, until stop is called. oneauth-server
// must trust the certificate (admin_auth.client_fetch_ca_file) and allow a
// loopback fetch (admin_auth.allow_private_client_hosts).
func ServeClientMetadata(addr, certFile, keyFile string, doc map[string]any) (stop func(), err error) {
	id, _ := doc["client_id"].(string)
	u, err := url.Parse(id)
	if err != nil || u.Path == "" {
		return nil, errors.New("the document's client_id has no path")
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+u.Path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write(body)
	})
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return func() { _ = srv.Close() }, nil
}

// WriteSelfSignedCert writes cert.pem and key.pem into dir: a P-256
// certificate for 127.0.0.1 that signs itself and is valid for a day. The
// exercise hands cert.pem to oneauth-server as client_fetch_ca_file, so the
// server trusts the document server built from it.
func WriteSelfSignedCert(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}
