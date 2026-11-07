package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Proxies are the reverse proxies in front of an addon whose forwarding
// headers it believes: the panel's ingress, nginx, a CDN. A request from one
// of them is taken to come from the address its X-Forwarded-For names, and
// to have come over HTTPS when its X-Forwarded-Proto says so. From anyone
// else both headers are the client's own words and mean nothing.
//
// The zero value trusts nobody: the connection's peer is the client.
type Proxies struct {
	prefixes []netip.Prefix
}

// ParseProxies reads a list of addresses and CIDR ranges separated by commas
// or spaces — the install's `trusted_proxies` answer. An entry that is
// neither is reported in the error and left out; the others are kept, so an
// addon may log the error and go on with what was understood.
func ParseProxies(list string) (Proxies, error) {
	var (
		p   Proxies
		bad []string
	)
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if pre, err := netip.ParsePrefix(f); err == nil {
			p.prefixes = append(p.prefixes, netip.PrefixFrom(pre.Addr().Unmap(), unmappedBits(pre)).Masked())
		} else if a, err := netip.ParseAddr(f); err == nil {
			a = a.Unmap()
			p.prefixes = append(p.prefixes, netip.PrefixFrom(a, a.BitLen()))
		} else {
			bad = append(bad, f)
		}
	}
	if len(bad) > 0 {
		return p, fmt.Errorf("trusted proxies: not an address or a range: %s", strings.Join(bad, ", "))
	}
	return p, nil
}

// unmappedBits is a prefix's length once its IPv4-mapped address is read
// as IPv4: ::ffff:10.0.0.0/104 is 10.0.0.0/8.
func unmappedBits(p netip.Prefix) int {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return p.Bits() - 96
	}
	return p.Bits()
}

// Empty reports whether no proxy is trusted.
func (p Proxies) Empty() bool { return len(p.prefixes) == 0 }

// Trusts reports whether an address (without a port) is a trusted proxy.
func (p Proxies) Trusts(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, pre := range p.prefixes {
		if pre.Contains(a) {
			return true
		}
	}
	return false
}

// peer is the connection's address without the port.
func peer(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ClientAddr is who a request is from: the peer, or — when the peer is a
// trusted proxy — the nearest address in X-Forwarded-For that is not one,
// read from the right, since the client writes the left of it itself.
func (p Proxies) ClientAddr(r *http.Request) string {
	host := peer(r)
	if !p.Trusts(host) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		host = a.Unmap().String()
		if !p.Trusts(host) {
			break
		}
	}
	return host
}

// Secure reports whether the browser reached the addon over HTTPS: the
// connection's own TLS, or a trusted proxy's X-Forwarded-Proto, its last
// entry — the one the nearest proxy wrote.
func (p Proxies) Secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !p.Trusts(peer(r)) {
		return false
	}
	protos := strings.Split(strings.Join(r.Header.Values("X-Forwarded-Proto"), ","), ",")
	return strings.EqualFold(strings.TrimSpace(protos[len(protos)-1]), "https")
}

type secureKey struct{}

// Handler puts the client's address, as ClientAddr finds it, in
// r.RemoteAddr — where auth.ClientAddr and every limit by address read it —
// and records Secure's answer for IsSecure. With no trusted proxy the
// address is left as it is.
func (p Proxies) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.WithContext(context.WithValue(r.Context(), secureKey{}, p.Secure(r)))
		if !p.Empty() {
			r2.RemoteAddr = net.JoinHostPort(p.ClientAddr(r), "0")
		}
		h.ServeHTTP(w, r2)
	})
}

// IsSecure reports whether the browser reached the addon over HTTPS, as the
// Proxies handler in front decided; without one, whether the connection
// itself is TLS. It is what a cookie's Secure flag should follow.
func IsSecure(r *http.Request) bool {
	if v, ok := r.Context().Value(secureKey{}).(bool); ok {
		return v
	}
	return r.TLS != nil
}

// RefuseCrossOrigin answers 403 to a state-changing request a browser sent
// from a page on another origin. SameSite=Strict keeps a cookie off a
// request from another site, but a sibling subdomain — another addon, the
// panel, a site beside them — is the same site, and a text/plain or form
// POST needs no preflight: without this, such a page could act with the
// admin's cookie. It is net/http's CrossOriginProtection (Sec-Fetch-Site,
// else Origin against Host); safe methods and requests with neither header —
// the panel, a payment gateway, curl — pass. bypass names patterns, in
// ServeMux syntax, that a browser on another origin is meant to reach, such
// as a gateway that returns its customer by a form POST.
func RefuseCrossOrigin(h http.Handler, bypass ...string) http.Handler {
	c := http.NewCrossOriginProtection()
	for _, pattern := range bypass {
		c.AddInsecureBypassPattern(pattern)
	}
	c.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"cross-origin request refused"}` + "\n"))
	}))
	return c.Handler(h)
}
