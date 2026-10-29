// Package web is what an addon's own web server needs to face the internet
// the way the panel does: its admin under a base path (the install's `path`
// option), its public pages where they are, HTTPS for its public address —
// a certificate from an ACME CA, or a self-signed one for an install reached
// by its IP — and a check that the public address reaches this very program.
package web

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/nx-panel/addon-kit/manifest"
)

// BasePath reads the install's base-path answer: "/admin", or "" for the
// root. It is manifest.NormalizeBasePath.
func BasePath(raw string) (string, error) { return manifest.NormalizeBasePath(raw) }

type baseKey struct{}

// BaseOf is the base path a request came in under: "" outside it, or when
// the addon has none. Under Mount, a redirect to one of h's own paths may be
// written with the base (BaseOf(ctx)+"/login"), without it ("/login"), or
// relative (http.Redirect(w, r, "login", …)): Mount puts the base on any
// root-relative Location that does not already name it. A redirect out of
// the admin — to a public page — is written as an absolute URL.
func BaseOf(ctx context.Context) string {
	b, _ := ctx.Value(baseKey{}).(string)
	return b
}

// CheckBase refuses a base path that is, or lies under, one of the public
// prefixes: the public page would win and the admin under it could not be
// reached. An addon calls it on the install's answer before Mount.
func CheckBase(base string, public ...string) error {
	if base == "" {
		return nil
	}
	for _, prefix := range public {
		if publicPath(base, []string{prefix}) || publicPath(base+"/", []string{prefix}) || strings.HasPrefix(prefix, base+"/") {
			return fmt.Errorf("the base path %s is taken by the public pages (%s); choose another", base, prefix)
		}
	}
	return nil
}

// Mount serves h under base, and at the root only the public prefixes —
// the pages an addon's customers open, which must not give the admin's path
// away. A prefix ending in "/" covers the tree under it; any other is one
// exact path. A public prefix wins over base, so a customer's page is never
// taken by an admin path that collides with it (CheckBase refuses those).
// Under base, h sees the path without it (BaseOf says what it was); at the
// root, the path as it came. Everything else answers 404 like a path
// nothing serves, never a redirect that would name the base. With no base,
// h serves everything.
func Mount(base string, h http.Handler, public ...string) http.Handler {
	if base == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case publicPath(p, public):
			h.ServeHTTP(w, r)
		case p == base:
			// Only someone who already has the path is sent on.
			target := base + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		case strings.HasPrefix(p, base+"/"):
			r2 := r.Clone(context.WithValue(r.Context(), baseKey{}, base))
			r2.URL.Path = strings.TrimPrefix(p, base)
			if r.URL.RawPath != "" {
				r2.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, base)
			}
			r2.RequestURI = r2.URL.RequestURI()
			h.ServeHTTP(&underBase{ResponseWriter: w, base: base, path: r2.URL.EscapedPath()}, r2)
		default:
			http.NotFound(w, r)
		}
	})
}

// underBase puts the base path on a redirect h wrote for its own paths,
// which h sees without it: ServeMux's (to a subtree's slash, or to the
// cleaned path, both built from the escaped path h saw), and any other
// root-relative Location that does not already name the base — including
// http.Redirect's, which resolves a relative URL against the path h saw.
type underBase struct {
	http.ResponseWriter
	base string
	path string // the escaped path h saw
}

func (u *underBase) WriteHeader(code int) {
	if code >= 300 && code < 400 {
		loc := u.Header().Get("Location")
		p := strings.SplitN(loc, "?", 2)[0]
		mux := p != u.path && (p == u.path+"/" || p == cleanPath(u.path))
		named := p == u.base || strings.HasPrefix(p, u.base+"/")
		if strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") && (mux || !named) {
			u.Header().Set("Location", u.base+loc)
		}
	}
	u.ResponseWriter.WriteHeader(code)
}

// cleanPath is path.Clean keeping a trailing slash, as ServeMux cleans.
func cleanPath(p string) string {
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// Unwrap lets http.ResponseController reach the connection's writer.
func (u *underBase) Unwrap() http.ResponseWriter { return u.ResponseWriter }

// Flush passes a streaming handler's flush on.
func (u *underBase) Flush() {
	if f, ok := u.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack hands the connection over, as the writer underneath would.
func (u *underBase) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := u.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("web: the connection cannot be taken over")
}

func publicPath(p string, public []string) bool {
	for _, prefix := range public {
		if strings.HasSuffix(prefix, "/") {
			if strings.HasPrefix(p, prefix) || p+"/" == prefix {
				return true
			}
		} else if p == prefix {
			return true
		}
	}
	return false
}

// CookiePath is the Path an admin session cookie takes: the base path's
// tree, so the browser never sends it anywhere else on the host.
func CookiePath(base string) string {
	if base == "" {
		return "/"
	}
	return base + "/"
}

// WhoAmI answers the program's own random name, for CheckAddress. An addon
// serves it on a path of its choosing, where its public address leads.
func WhoAmI(instance string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, instance)
	})
}

// selfSignedClient asks an address with a self-signed certificate. It is
// shared, so its idle connections are reused and time out, not leaked.
var selfSignedClient = &http.Client{Transport: &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // a self-signed certificate has no CA to check; the answer's instance name is what is checked
	IdleConnTimeout: 30 * time.Second,
}}

// CheckAddress asks target — the public address and the WhoAmI path, as a
// visitor would reach it — whether it answers with instance: an address
// that answers with another name reaches another program. selfSigned skips
// the certificate's check, which a self-signed certificate never passes;
// what is checked then is only that the program answering is this one, not
// that the certificate is (TLS.Fingerprint is for the admin to compare).
func CheckAddress(ctx context.Context, target, instance string, selfSigned bool) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	client := http.DefaultClient
	if selfSigned {
		client = selfSignedClient
	}
	resp, err := client.Do(req)
	if err != nil {
		var cert *tls.CertificateVerificationError
		if errors.As(err, &cert) {
			return errors.New("the address answers, but its certificate is not valid")
		}
		return fmt.Errorf("the address does not answer: %v", shortErr(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if strings.TrimSpace(string(body)) != instance {
		return errors.New("the address answers, but not with this program")
	}
	return nil
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 120 {
		return s[i+2:]
	}
	return s
}
