package core

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedProxies lists the addresses whose X-Forwarded-For / X-Real-IP
// headers are believed: the reverse proxies or load balancers in front of
// this process. Empty means none, so the client address is always the TCP
// peer.
type TrustedProxies []netip.Prefix

// ParseTrustedProxies parses CIDRs ("10.0.0.0/8") and single addresses
// ("192.0.2.10") into TrustedProxies.
func ParseTrustedProxies(entries []string) (TrustedProxies, error) {
	var out TrustedProxies
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", e, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", e, err)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Contains reports whether addr is one of the trusted proxies.
func (tp TrustedProxies) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range tp {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP returns the address a request came from, for rate limiting and
// logging. X-Forwarded-For is client-supplied, so it is read only when the
// TCP peer is a trusted proxy (CWE-348); otherwise anyone could put a fresh
// address in every request and get a fresh rate-limit bucket each time.
//
// Behind trusted proxies the header is walked right to left, skipping
// trusted hops, and the first address that isn't a trusted proxy is the
// client. Entries to its left were written by the client and are ignored.
// X-Real-IP is used only when a trusted peer sent no X-Forwarded-For.
func ClientIP(r *http.Request, trusted TrustedProxies) string {
	peerStr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peerStr); err == nil {
		peerStr = host
	}
	peer, err := netip.ParseAddr(peerStr)
	if err != nil || !trusted.Contains(peer) {
		return peerStr
	}

	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		hops := strings.Split(strings.Join(xff, ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				return peer.String()
			}
			if !trusted.Contains(hop) {
				return hop.Unmap().String()
			}
		}
		return peer.String()
	}
	if xri, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return xri.Unmap().String()
	}
	return peer.String()
}
