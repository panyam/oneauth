package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// serverCSP is the Content-Security-Policy for every response. Pages load
// only this server's own stylesheet (static/app.css, built from the
// templates by `make server-css`), so there is no third-party script and no
// inline style to allow (CWE-829).
var serverCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"

//go:embed static/app.css
var staticFS embed.FS

// staticHandler serves the embedded stylesheet under /static/.
func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}

// checkTransport refuses to start a server whose public URL is plain http
// on anything but a loopback host, because every credential the server
// handles would cross the network in cleartext (OAuth 2.1 §1.5, CWE-319).
// Behind a TLS-terminating proxy, set server.public_url to the https URL
// clients use. server.allow_insecure_http overrides it for a private
// network (docker-compose service names, say).
func checkTransport(cfg *Config) error {
	base := publicBaseURL(cfg)
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("server.public_url %q: %w", base, err)
	}
	if u.Scheme == "https" || isLoopbackHost(u.Hostname()) {
		return nil
	}
	if cfg.Server.AllowInsecureHTTP {
		log.Printf("WARNING: serving %s over plain http (server.allow_insecure_http). Credentials cross the network in cleartext.", base)
		return nil
	}
	return fmt.Errorf("refusing to serve %s over plain http: set server.public_url to the https URL clients use (TLS at a proxy is fine), or server.allow_insecure_http: true for a private network", base)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// minHMACSecret is the shortest jwt.secret_key accepted: RFC 7518 §3.2 has
// an HS256 key be at least the hash size.
const minHMACSecret = 32

// checkSigningSecret refuses a jwt.secret_key shorter than 32 bytes. It
// signs browser sessions in every mode and access tokens under HS256, and
// an empty one would let anyone mint both.
func checkSigningSecret(cfg *Config) error {
	if n := len(cfg.JWT.SecretKey); n < minHMACSecret {
		return fmt.Errorf("jwt.secret_key (JWT_SECRET_KEY) must be at least %d bytes, got %d; generate one with: openssl rand -hex 32", minHMACSecret, n)
	}
	return nil
}
