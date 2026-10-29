package web_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nx-panel/addon-kit/web"
)

// echo answers the path it saw and the base it came under.
var echo = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s|%s", r.URL.Path, web.BaseOf(r.Context()))
})

func get(t *testing.T, h http.Handler, path string) (int, string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String(), rec.Header().Get("Location")
}

// TestTheAdminIsUnderItsBaseAndThePublicPagesAreNot: the admin answers only
// under its base path, which it sees stripped; the public prefixes answer at
// the root; everything else — the root, the admin's own paths without the
// base, a near miss — is a plain 404 that names nothing.
func TestTheAdminIsUnderItsBaseAndThePublicPagesAreNot(t *testing.T) {
	h := web.Mount("/k9x2", echo, "/app/", "/pay/", "/whoami")
	for _, c := range []struct {
		path string
		code int
		body string
	}{
		{"/k9x2/api/status", 200, "/api/status|/k9x2"},
		{"/k9x2/", 200, "/|/k9x2"},
		{"/app/", 200, "/app/|"},
		{"/app/assets/x.js", 200, "/app/assets/x.js|"},
		{"/app", 200, "/app|"},
		{"/pay/hook/gateway-1", 200, "/pay/hook/gateway-1|"},
		{"/whoami", 200, "/whoami|"},
		{"/whoami/x", 404, ""},
		{"/", 404, ""},
		{"/api/status", 404, ""},
		{"/k9x2x/api", 404, ""},
		{"/K9X2/api", 404, ""},
	} {
		code, body, _ := get(t, h, c.path)
		if code != c.code || (c.body != "" && body != c.body) {
			t.Errorf("%s = %d %q, want %d %q", c.path, code, body, c.code, c.body)
		}
		if code == 404 && strings.Contains(body, "k9x2") {
			t.Errorf("%s: the 404 names the base path: %q", c.path, body)
		}
	}
	if code, _, loc := get(t, h, "/k9x2?x=1"); code != http.StatusMovedPermanently || loc != "/k9x2/?x=1" {
		t.Errorf("the bare base = %d %q", code, loc)
	}
	if code, body, _ := get(t, web.Mount("", echo, "/app/"), "/api/status"); code != 200 || body != "/api/status|" {
		t.Errorf("no base = %d %q", code, body)
	}
	if web.CookiePath("/k9x2") != "/k9x2/" || web.CookiePath("") != "/" {
		t.Error("the cookie paths")
	}
}

// TestTheAddressCheckKnowsItsOwnProgram: the address answering with this
// program's name passes; another program's fails; a self-signed
// certificate fails the ordinary check and passes when it is expected.
func TestTheAddressCheckKnowsItsOwnProgram(t *testing.T) {
	plain := httptest.NewServer(web.WhoAmI("me-123"))
	defer plain.Close()
	ctx := context.Background()
	if err := web.CheckAddress(ctx, plain.URL, "me-123", false); err != nil {
		t.Fatalf("its own address: %v", err)
	}
	if err := web.CheckAddress(ctx, plain.URL, "someone-else", false); err == nil || !strings.Contains(err.Error(), "not with this program") {
		t.Fatalf("another program's: %v", err)
	}
	secure := httptest.NewTLSServer(web.WhoAmI("me-123"))
	defer secure.Close()
	if err := web.CheckAddress(ctx, secure.URL, "me-123", false); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("an untrusted certificate: %v", err)
	}
	if err := web.CheckAddress(ctx, secure.URL, "me-123", true); err != nil {
		t.Fatalf("a self-signed certificate, expected: %v", err)
	}
}

func serveTLS(t *testing.T, tl *web.TLS) (*x509Peer, func()) {
	t.Helper()
	cfg, err := tl.Config()
	if err != nil {
		t.Fatal(err)
	}
	// A listener of its own: httptest's would serve its own certificate.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })}
	go func() { _ = srv.Serve(ln) }()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // the test reads the certificate itself
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		_ = srv.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	leaf := resp.TLS.PeerCertificates[0]
	return &x509Peer{raw: leaf.Raw, ips: fmt.Sprint(leaf.IPAddresses), dns: leaf.DNSNames, days: int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)}, func() { _ = srv.Close() }
}

type x509Peer struct {
	raw  []byte
	ips  string
	dns  []string
	days int
}

func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// TestASelfSignedCertificateNamesTheAddressAndIsKept: an install reached by
// its IP gets a certificate for that IP, within the 398 days browsers
// accept; the fingerprint shown is the one served; a restart keeps the same
// certificate; a new address gets a new one.
func TestASelfSignedCertificateNamesTheAddressAndIsKept(t *testing.T) {
	dir := t.TempDir()
	host := "127.0.0.1"
	tl := &web.TLS{Mode: web.HTTPSSelfSigned, Host: func() string { return host }, Dir: dir}
	peer, stop := serveTLS(t, tl)
	stop()
	if peer.ips != "[127.0.0.1]" || peer.days > 398 {
		t.Fatalf("the certificate names %s %v for %d days", peer.ips, peer.dns, peer.days)
	}
	if got := tl.Fingerprint(); got != fingerprint(peer.raw) {
		t.Fatalf("Fingerprint = %s, served %s", got, fingerprint(peer.raw))
	}
	again := &web.TLS{Mode: web.HTTPSSelfSigned, Host: func() string { return host }, Dir: dir}
	if again.Fingerprint() != fingerprint(peer.raw) {
		t.Fatal("a restart made a new certificate")
	}
	host = "notif.example.org"
	if again.Fingerprint() == fingerprint(peer.raw) {
		t.Fatal("a new address kept the old certificate")
	}
	if web.HostOf("https://Shop.Example.com:8443/x9") != "shop.example.com" || web.HostOf("shop.example.com") != "" {
		t.Fatal("HostOf")
	}
}

// TestACMESignsOnlyThePublicDomain: ACME refuses a name that is not the
// public address's, and an address by IP, before it asks any CA.
func TestACMESignsOnlyThePublicDomain(t *testing.T) {
	host := "shop.example.com"
	tl := &web.TLS{Mode: web.HTTPSACME, Host: func() string { return host }, Dir: t.TempDir()}
	cfg, err := tl.Config()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); err == nil || !strings.Contains(err.Error(), "not the public address") {
		t.Fatalf("another name: %v", err)
	}
	host = "203.0.113.7"
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "203.0.113.7"}); err == nil {
		t.Fatal("an address by IP went to the CA")
	}
	if _, err := (&web.TLS{Mode: "letsencrypt", Host: func() string { return host }}).Config(); err == nil {
		t.Fatal("an unknown mode")
	}
}

// TestABaseThatTakesAPublicPageIsRefused: a base path equal to, or under,
// a customer page would hide one or the other; CheckBase refuses it, and
// Mount keeps the customer's page if it is used anyway.
func TestABaseThatTakesAPublicPageIsRefused(t *testing.T) {
	for _, base := range []string{"/pay", "/app", "/whoami"} {
		if web.CheckBase(base, "/app/", "/pay/", "/whoami") == nil {
			t.Errorf("CheckBase(%s) took it", base)
		}
	}
	if err := web.CheckBase("/k9x2", "/app/", "/pay/", "/whoami"); err != nil {
		t.Fatal(err)
	}
	h := web.Mount("/pay", echo, "/app/", "/pay/")
	if code, body, _ := get(t, h, "/pay/hook/gateway-1"); code != 200 || body != "/pay/hook/gateway-1|" {
		t.Fatalf("the gateway's callback = %d %q", code, body)
	}
}

// TestARedirectUnderTheBaseKeepsIt: ServeMux's own redirects — a subtree's
// missing slash, an unclean path — are written for the path the admin sees,
// without the base; Mount puts it back.
func TestARedirectUnderTheBaseKeepsIt(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "asset") })
	h := web.Mount("/k9x2", mux, "/app/")
	for path, want := range map[string]string{"/k9x2/assets": "/k9x2/assets/", "/k9x2//assets/": "/k9x2/assets/"} {
		code, _, loc := get(t, h, path)
		if code < 300 || code >= 400 || loc != want {
			t.Errorf("%s = %d %q, want a redirect to %s", path, code, loc, want)
		}
	}
}

// TestARedirectThatNamesTheBaseIsLeftAlone: a handler that builds its
// redirect with BaseOf gets it as written; a streaming handler can flush.
func TestARedirectThatNamesTheBaseIsLeftAlone(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, web.BaseOf(r.Context())+"/home", http.StatusFound)
	})
	mux.HandleFunc("GET /stream", func(w http.ResponseWriter, _ *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
		}
	})
	h := web.Mount("/k9x2", mux)
	if code, _, loc := get(t, h, "/k9x2/login"); code != http.StatusFound || loc != "/k9x2/home" {
		t.Fatalf("a redirect built with BaseOf = %d %q", code, loc)
	}
	if code, body, _ := get(t, h, "/k9x2/stream"); code != http.StatusOK {
		t.Fatalf("a streaming handler = %d %q", code, body)
	}
}

// TestAnAdminRouteNamedLikeTheBaseOrAPublicPage: ServeMux's slash redirect
// for h's own /admin/ or /sub/ subtree gets the base, though its text looks
// like the base or a public page.
func TestAnAdminRouteNamedLikeTheBaseOrAPublicPage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/", func(w http.ResponseWriter, _ *http.Request) {})
	mux.HandleFunc("GET /sub/", func(w http.ResponseWriter, _ *http.Request) {})
	h := web.Mount("/admin", mux, "/pay/")
	for path, want := range map[string]string{"/admin/admin": "/admin/admin/", "/admin/sub": "/admin/sub/"} {
		if code, _, loc := get(t, h, path); code < 300 || code >= 400 || loc != want {
			t.Errorf("%s = %d %q, want a redirect to %s", path, code, loc, want)
		}
	}
}

// TestRelativeAndEscapedRedirectsKeepTheBase: http.Redirect resolves a
// relative URL against the path h saw, and ServeMux redirects with the
// escaped path; both come back under the base.
func TestRelativeAndEscapedRedirectsKeepTheBase(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "login", http.StatusFound) })
	mux.HandleFunc("GET /users/{id}/edit", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "../list", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /people/{id}/", func(w http.ResponseWriter, _ *http.Request) {})
	h := web.Mount("/k9x2", mux)
	for path, want := range map[string]string{
		"/k9x2/":               "/k9x2/login",
		"/k9x2/users/7/edit":   "/k9x2/users/list",
		"/k9x2/people/ali%20r": "/k9x2/people/ali%20r/",
		"/k9x2/people/%C3%BC":  "/k9x2/people/%C3%BC/",
		"/k9x2/people//x":      "/k9x2/people/x/",
	} {
		if code, _, loc := get(t, h, path); code < 300 || code >= 400 || loc != want {
			t.Errorf("%s = %d %q, want a redirect to %s", path, code, loc, want)
		}
	}
}

// TestServeLetsTheRequestsInHandFinish: Serve returns only once a request
// running when ctx ends has had its answer.
func TestServeLetsTheRequestsInHandFinish(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	started := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(400 * time.Millisecond)
		_, _ = io.WriteString(w, "done")
	})
	tl := &web.TLS{Mode: web.HTTPSSelfSigned, Host: func() string { return "127.0.0.1" }, Dir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- tl.Serve(ctx, addr, h) }()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a test server's own certificate
	got := make(chan string, 1)
	go func() {
		for range 50 {
			resp, err := client.Get("https://" + addr)
			if err != nil {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			got <- string(b)
			return
		}
		got <- "unreachable"
	}()
	<-started
	cancel()
	select {
	case err := <-served:
		t.Fatalf("Serve returned (%v) before the request in hand finished", err)
	case body := <-got:
		if body != "done" {
			t.Fatalf("the request in hand got %q", body)
		}
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}
