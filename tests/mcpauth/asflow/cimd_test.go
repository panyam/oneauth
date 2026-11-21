package asflow

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// The exercise trusts only the generated cert, as oneauth-server does
// through client_fetch_ca_file, and fetches the document at its client_id.
func TestServeClientMetadata_ServesTheDocumentAtItsClientIDOverTrustedTLS(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSelfSignedCert(dir); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	docURL := "https://" + addr + "/client.json"
	stop, err := ServeClientMetadata(addr, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), ClientMetadataDocument(docURL, "http://127.0.0.1:18400/callback"))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	pemBytes, _ := os.ReadFile(filepath.Join(dir, "cert.pem"))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("cert.pem doesn't parse")
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	resp, err := hc.Get(docURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["client_id"] != docURL {
		t.Errorf("client_id = %v, want %s", doc["client_id"], docURL)
	}
	if _, has := doc["token_endpoint_auth_method"]; has {
		t.Error("a public client leaves token_endpoint_auth_method out, which means none")
	}
	if doc["client_name"] == "" || doc["redirect_uris"] == nil {
		t.Error("MCP requires client_name and redirect_uris")
	}

	if resp, err := hc.Get("https://" + addr + "/other.json"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("another path answered %d", resp.StatusCode)
		}
	}
}
