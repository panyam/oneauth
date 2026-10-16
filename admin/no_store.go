package admin

import "net/http"

// noStore marks a response as uncacheable. Admin and registration
// responses carry client secrets and registration access tokens, which
// RFC 6749 §5.1 (pointed to by RFC 7591 §3.2.1) keeps out of caches.
func noStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}
