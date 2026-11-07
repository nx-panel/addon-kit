package web_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nx-panel/addon-kit/auth"
	"github.com/nx-panel/addon-kit/web"
)

func TestParseProxies(t *testing.T) {
	p, err := web.ParseProxies("127.0.0.1, 10.0.0.0/8 ::1 ::ffff:192.168.0.0/112")
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "10.20.30.40": true, "::1": true, "192.168.7.9": true,
		"::ffff:10.1.1.1": true, "11.0.0.1": false, "198.51.100.7": false, "nonsense": false,
	} {
		if got := p.Trusts(addr); got != want {
			t.Errorf("Trusts(%s) = %v, want %v", addr, got, want)
		}
	}
	p, err = web.ParseProxies("127.0.0.1, panel.local, 10.0.0.0/33")
	if err == nil || !strings.Contains(err.Error(), "panel.local") || !strings.Contains(err.Error(), "10.0.0.0/33") {
		t.Errorf("err = %v, want both bad entries named", err)
	}
	if !p.Trusts("127.0.0.1") {
		t.Error("the good entry was dropped with the bad ones")
	}
	if p, _ := web.ParseProxies(""); !p.Empty() {
		t.Error("an empty list trusts someone")
	}
}

func req(remote string, header http.Header) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, v := range header {
		r.Header[k] = v
	}
	return r
}

// TestBehindATrustedProxyTheClientIsTheForwardedOne is why it exists: behind
// the panel's ingress or nginx every connection is the proxy's, so a limiter
// keyed on the peer locks every admin out after one stranger's five tries.
func TestBehindATrustedProxyTheClientIsTheForwardedOne(t *testing.T) {
	p, _ := web.ParseProxies("127.0.0.1")
	var seen string
	h := p.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = auth.ClientAddr(r) }))
	cases := []struct {
		remote, xff, want string
	}{
		{"127.0.0.1:5000", "203.0.113.7", "203.0.113.7"},
		// The client wrote the left part itself; the proxy appended the right.
		{"127.0.0.1:5000", "6.6.6.6, 203.0.113.7", "203.0.113.7"},
		// From anyone else the header is the client's own word.
		{"198.51.100.9:5000", "203.0.113.7", "198.51.100.9"},
		{"127.0.0.1:5000", "", "127.0.0.1"},
		{"127.0.0.1:5000", "not-an-address", "127.0.0.1"},
	}
	for _, tc := range cases {
		h.ServeHTTP(httptest.NewRecorder(), req(tc.remote, http.Header{"X-Forwarded-For": {tc.xff}}))
		if seen != tc.want {
			t.Errorf("peer %s, XFF %q: client = %s, want %s", tc.remote, tc.xff, seen, tc.want)
		}
	}

	// Trusting nobody leaves the address alone.
	var none web.Proxies
	h = none.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = auth.ClientAddr(r) }))
	h.ServeHTTP(httptest.NewRecorder(), req("127.0.0.1:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}))
	if seen != "127.0.0.1" {
		t.Errorf("no proxies: client = %s, want the peer", seen)
	}
}

// TestSecureIsTheConnectionsOrATrustedProxys: a cookie's Secure flag follows
// it, so a client cannot talk an addon behind no proxy into anything with a
// header of its own.
func TestSecureIsTheConnectionsOrATrustedProxys(t *testing.T) {
	p, _ := web.ParseProxies("127.0.0.1")
	var secure bool
	h := p.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { secure = web.IsSecure(r) }))
	https := http.Header{"X-Forwarded-Proto": {"https"}}
	for _, tc := range []struct {
		name   string
		r      *http.Request
		secure bool
	}{
		{"trusted proxy says https", req("127.0.0.1:1", https), true},
		{"trusted proxy says http", req("127.0.0.1:1", http.Header{"X-Forwarded-Proto": {"http"}}), false},
		{"the nearest proxy's word counts", req("127.0.0.1:1", http.Header{"X-Forwarded-Proto": {"https, http"}}), false},
		{"a stranger says https", req("198.51.100.9:1", https), false},
		{"no header", req("127.0.0.1:1", nil), false},
	} {
		h.ServeHTTP(httptest.NewRecorder(), tc.r)
		if secure != tc.secure {
			t.Errorf("%s: secure = %v, want %v", tc.name, secure, tc.secure)
		}
	}
	r := req("198.51.100.9:1", nil)
	r.TLS = &tls.ConnectionState{}
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !secure {
		t.Error("a TLS connection is not secure")
	}
	// Outside the handler: the connection alone.
	if web.IsSecure(req("127.0.0.1:1", https)) {
		t.Error("without the handler, a header made a request secure")
	}
}

// TestRefuseCrossOrigin: a page on a sibling subdomain is the same site, so
// a SameSite=Strict cookie goes with its requests; the write is refused, the
// addon's own pages and servers calling it are not.
func TestRefuseCrossOrigin(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := web.RefuseCrossOrigin(ok, "POST /pay/hook/{method}")
	post := func(path string, header http.Header) int {
		r := httptest.NewRequest(http.MethodPost, "http://shop.example.com"+path, strings.NewReader("{}"))
		for k, v := range header {
			r.Header[k] = v
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	for _, tc := range []struct {
		name   string
		path   string
		header http.Header
		want   int
	}{
		{"sibling subdomain", "/api/settings", http.Header{"Sec-Fetch-Site": {"same-site"}}, http.StatusForbidden},
		{"another site", "/api/settings", http.Header{"Sec-Fetch-Site": {"cross-site"}}, http.StatusForbidden},
		{"old browser, other origin", "/api/settings", http.Header{"Origin": {"https://panel.example.com"}}, http.StatusForbidden},
		{"the addon's own page", "/api/settings", http.Header{"Sec-Fetch-Site": {"same-origin"}}, http.StatusNoContent},
		{"a server", "/api/settings", nil, http.StatusNoContent},
		{"a bypassed path", "/pay/hook/zarinpal", http.Header{"Sec-Fetch-Site": {"cross-site"}}, http.StatusNoContent},
	} {
		if got := post(tc.path, tc.header); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Errorf("a cross-site GET: %d, want it through", rec.Code)
	}
}
