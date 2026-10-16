package apiauth

import "net/http"

// noStore marks a response as uncacheable. RFC 6749 §5.1 requires it on
// every response carrying a token or credential, and OAuth 2.1 §3.2.4 on
// token errors too; Pragma covers HTTP/1.0 caches.
func noStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}
