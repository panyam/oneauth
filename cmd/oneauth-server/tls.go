package main

import "crypto/tls"

// bcp195CipherSuites are the TLS 1.2 suites RFC 9325 §4.2 recommends:
// ECDHE key exchange with AES-GCM. FAPI 2.0 §5.2.1 requires BCP 195, and the
// OIDF harness accepts only these on TLS 1.2. Go doesn't let a server choose
// its TLS 1.3 suites, all of which are AEAD.
var bcp195CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// serverTLSConfig is the TLS configuration the server uses when it
// terminates TLS itself (tls.enabled): TLS 1.2 or later, and on 1.2 only
// the BCP 195 suites, so the CBC suites Go still enables by default are
// refused (issue 440).
func serverTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: bcp195CipherSuites,
	}
}
