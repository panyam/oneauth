package httpauth

import (
	"io"
	"net/http"
)

// DefaultMaxBodySize is the default request body size limit (1MB).
const DefaultMaxBodySize = 1 << 20 // 1MB

// LimitBody returns middleware that limits the request body to maxBytes.
// If the body exceeds the limit, a 413 Request Entity Too Large response is
// sent before the handler runs. This prevents memory exhaustion from oversized
// JSON bodies (CWE-400: Uncontrolled Resource Consumption).
//
// Usage:
//
//	mux.Handle("/api/login", httpauth.LimitBody(1<<20)(loginHandler))
//
// Or wrap an entire mux:
//
//	http.ListenAndServe(":8080", httpauth.LimitBody(1<<20)(mux))
func LimitBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.ContentLength > maxBytes {
				http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			// Also set MaxBytesReader as a safety net for chunked transfers
			// where ContentLength may be -1
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// LimitBodyReader is a lower-level helper that wraps a request body with
// http.MaxBytesReader. Unlike LimitBody middleware, it doesn't reject upfront —
// the error occurs when the handler tries to read past the limit.
// Use this when you need to apply limits inside a handler rather than as middleware.
func LimitBodyReader(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
}

// IsBodyTooLargeError checks if an error is from http.MaxBytesReader exceeding its limit.
func IsBodyTooLargeError(err error) bool {
	if err == nil {
		return false
	}
	// http.MaxBytesReader returns *http.MaxBytesError in Go 1.19+
	_, ok := err.(*http.MaxBytesError)
	if ok {
		return true
	}
	// Fallback for reading errors
	return err == io.ErrUnexpectedEOF
}
