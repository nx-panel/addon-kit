// Package manifest is the NX addon contract: the manifest an addon
// keeps as nx-addon.json at the root of its repository and serves at
// /.well-known/nx-addon.json, its signature, and the body the panel
// delivers an addon's credentials in. The panel, the directory at
// addons.nx-panel.org and an addon all read it through this package,
// so they cannot disagree about what a valid manifest is.
//
// Two versions are spoken. `api: 0` is what a running addon serves for
// registration; `api: 1` adds what the directory and the install wizard read
// before anything runs — the install section and its questions,
// descriptions, the panel it needs (install.go). Version 1 is frozen with
// the first release of NX Shop; until then it may still change. The
// specification is SPEC.md beside this module.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// API is the newest manifest version; APIs is every one a panel accepts.
const API = 1

// APIs are the manifest versions a panel accepts.
var APIs = []int{0, 1}

// FileName is the manifest's name at the root of an addon's repository.
const FileName = "nx-addon.json"

// WellKnownPath is where an addon serves its manifest, under its base URL.
const WellKnownPath = "/.well-known/nx-addon.json"

// MaxManifestSize caps what the panel reads from an addon. A manifest is a
// few hundred bytes; the cap is there so a wrong URL cannot stream a file in.
const MaxManifestSize = 64 << 10

// slugPattern is the one spelling of an addon id: the token's addon and the
// manifest's slug.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidSlug reports whether s is a usable addon id.
func ValidSlug(s string) bool { return slugPattern.MatchString(s) }

// Scope is one permission the addon's token asks for, with the reason shown
// to the main admin on the consent screen.
type Scope struct {
	Scope   string `json:"scope"`
	Purpose string `json:"purpose"`
}

// Manifest is what an addon declares. The panel creates exactly what it
// declares and nothing else: an API token when Scopes is not empty, an event
// subscription when Webhook is set, both when both are.
type Manifest struct {
	API       int    `json:"api"`
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	// Scopes is the token's permission set; empty means no token.
	Scopes []Scope `json:"scopes,omitempty"`
	// Events is what the subscription hears; it is required with Webhook.
	Events []string `json:"events,omitempty"`
	// Webhook, Setup and Health are paths under the base URL the addon was
	// registered at. Setup is where the credentials are delivered, and is
	// required; Health is polled when present.
	Webhook string `json:"webhook,omitempty"`
	Setup   string `json:"setup"`
	Health  string `json:"health,omitempty"`
	// UI is the addon's entry point, a path under the base URL or an absolute
	// URL; the panel shows it as a link, never in a frame.
	UI string `json:"ui,omitempty"`

	// Api 1: what the directory and the install wizard read (install.go).
	// Description is by language, English required when given.
	Description map[string]string `json:"description,omitempty"`
	License     string            `json:"license,omitempty"`
	Paid        bool              `json:"paid,omitempty"`
	Docs        string            `json:"docs,omitempty"`
	Requires    *Requires         `json:"requires,omitempty"`
	Install     *Install          `json:"install,omitempty"`
	// RateLimit is the requests a minute the addon's token may make, from 1
	// to MaxRateLimit; 0 is the panel's default (120). Shown on the consent
	// screen, and a newer manifest asking more waits for approval like a
	// new scope.
	RateLimit int `json:"rateLimit,omitempty"`

	// Signature is the Ed25519 signature over everything else (see
	// SigningPayload), base64.
	Signature string `json:"signature,omitempty"`
}

// v1Only reports whether a manifest uses a field api 0 does not have.
func (m Manifest) v1Only() bool {
	return len(m.Description) > 0 || m.License != "" || m.Paid || m.Docs != "" || m.Requires != nil || m.Install != nil ||
		m.RateLimit != 0
}

// Parse decodes and checks a manifest's shape. The panel's own vocabulary —
// whether a scope or an event exists — is the caller's to check; this
// package does not know the catalogs.
func Parse(raw []byte) (Manifest, error) {
	if err := noDuplicateKeys(raw); err != nil {
		return Manifest{}, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Manifest{}, fmt.Errorf("the manifest is not a JSON object: %w", err)
	}
	if _, ok := probe["api"]; !ok {
		return Manifest{}, errors.New("the manifest names no api version")
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("the manifest does not parse: %w", err)
	}
	return m, m.Check()
}

// Check is the shape every manifest must have.
func (m Manifest) Check() error {
	switch {
	case !slices.Contains(APIs, m.API):
		return fmt.Errorf("the manifest speaks api %d; this panel speaks api 0 and 1 — update the panel", m.API)
	case m.API == 0 && m.v1Only():
		return errors.New("the manifest says api 0 but uses api 1 fields (description, license, paid, docs, requires, install, rateLimit)")
	case !ValidSlug(m.Slug):
		return errors.New("slug must be a short lowercase id (a-z, 0-9, _ and -, at most 32)")
	case strings.TrimSpace(m.Name) == "" || len(m.Name) > 64:
		return errors.New("name is required (at most 64 characters)")
	case len(m.Version) > 32 || len(m.Publisher) > 64:
		return errors.New("version or publisher is too long")
	case len(m.Scopes) == 0 && m.Webhook == "":
		return errors.New("the manifest asks for neither a token (scopes) nor a webhook")
	case m.Webhook != "" && len(m.Events) == 0:
		return errors.New("a webhook needs the events it is for")
	case m.Webhook == "" && len(m.Events) > 0:
		return errors.New("events are delivered to a webhook, and the manifest names none")
	case m.Setup == "":
		return errors.New("setup is required: it is where the credentials are delivered")
	}
	served := map[string]string{WellKnownPath: "the manifest's own path"}
	for _, f := range []struct{ name, path string }{{"setup", m.Setup}, {"webhook", m.Webhook}, {"health", m.Health}} {
		if f.path == "" {
			continue
		}
		if !ValidPath(f.path) {
			return fmt.Errorf("%s must be a clean path under the addon's address: starting with /, no empty, . or .. segment, and none of ? # %% { } \\ or spaces", f.name)
		}
		// The kit serves each on its own route: two on one path cannot be.
		if other, taken := served[f.path]; taken {
			return fmt.Errorf("%s is the same path as %s", f.name, other)
		}
		served[f.path] = f.name
	}
	if m.UI != "" && !ValidPath(m.UI) && !absoluteHTTP(m.UI) {
		return errors.New("ui must be a path under the addon's address or an absolute http(s) URL")
	}
	seen := map[string]bool{}
	for _, s := range m.Scopes {
		if s.Scope == "" || strings.TrimSpace(s.Purpose) == "" {
			return errors.New("every scope needs its purpose")
		}
		if seen[s.Scope] {
			return fmt.Errorf("scope %s is listed twice", s.Scope)
		}
		seen[s.Scope] = true
	}
	seen = map[string]bool{}
	for _, e := range m.Events {
		if e == "" || seen[e] {
			return fmt.Errorf("event %q is empty or listed twice", e)
		}
		seen[e] = true
	}
	if m.API >= 1 {
		return checkV1(m)
	}
	return nil
}

// ScopeNames is the token's scope list.
func (m Manifest) ScopeNames() []string {
	out := make([]string, 0, len(m.Scopes))
	for _, s := range m.Scopes {
		out = append(out, s.Scope)
	}
	return out
}

// ValidPath is a path under a base URL: it starts with one slash, carries no
// scheme, host, query or fragment, and never climbs out with "..".
func ValidPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || len(p) > 512 {
		return false
	}
	// { and } are the route patterns' own syntax, and a %-escape is matched
	// unescaped: a path with any of them would be a different route from the
	// one the manifest names, or the same route as another of its paths.
	if strings.ContainsAny(p, "?#\\ \t\r\n{}%") {
		return false
	}
	// A clean path only: no "." or ".." segment, and no empty one but a
	// trailing slash — a route with any other can never match.
	segs := strings.Split(p[1:], "/")
	for i, seg := range segs {
		if seg == "." || seg == ".." || (seg == "" && i != len(segs)-1) {
			return false
		}
	}
	return true
}

func absoluteHTTP(s string) bool {
	return (strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")) && len(s) <= 2048
}

// Join puts a manifest path under the base URL it was registered at. The base
// carries no trailing slash (NormalizeBase), so an addon at a sub-path keeps
// it: https://x/shop + /setup = https://x/shop/setup.
func Join(base, path string) string {
	if absoluteHTTP(path) {
		return path
	}
	return base + path
}

// SetupRequest is what the panel POSTs to the addon's setup path once the
// main admin has approved it. ClaimCode is the code the addon showed: the
// addon accepts its credentials only with it, which is what stops anyone
// else claiming it. Token is the API token in plain text, shown nowhere
// else; Webhook carries the signing secret of the subscription. Either is
// absent when the manifest did not ask for it.
type SetupRequest struct {
	API       int           `json:"api"`
	ClaimCode string        `json:"claimCode"`
	Panel     SetupPanel    `json:"panel"`
	Token     string        `json:"token,omitempty"`
	Scopes    []string      `json:"scopes,omitempty"`
	Webhook   *SetupWebhook `json:"webhook,omitempty"`
}

// SetupPanel says where the panel is, as the main admin's browser reached it.
// An addon that is configured with the panel's address keeps its own.
type SetupPanel struct {
	URL     string `json:"url"`
	Version string `json:"version"`
	// ID names the panel install, stable across address changes; absent
	// from panels that predate it.
	ID string `json:"id,omitempty"`
	// PublicURL is the address the operator gave the panel for people to
	// use — its public address setting, with the panel's base path — which
	// URL is not when the admin's browser reached the panel by another name.
	// Absent when no public address is set.
	PublicURL string `json:"publicUrl,omitempty"`
}

// SetupWebhook is the subscription made for the addon.
type SetupWebhook struct {
	ID     uint     `json:"id"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret"`
}

// Compact re-encodes a JSON value without insignificant whitespace, so the
// manifest the panel stores is one line whatever the addon served.
func Compact(raw []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return raw
	}
	return buf.Bytes()
}

// NormalizeBase checks an addon's base URL and returns it without a trailing
// slash: absolute http(s), a host, no credentials, query or fragment. Whether
// plain http is allowed for it is the caller's question, since it
// depends on where the name resolves.
func NormalizeBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("the address must be an absolute http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("the address must not carry credentials, a query or a fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}
