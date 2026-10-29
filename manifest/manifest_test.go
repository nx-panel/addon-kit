package manifest_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	addon "github.com/nx-panel/addon-kit/manifest"
)

func sample() addon.Manifest {
	return addon.Manifest{
		API: addon.API, Slug: "shop", Name: "Shop", Version: "1.0.0", Publisher: "NX",
		Scopes:  []addon.Scope{{Scope: "users:read", Purpose: "to list the accounts it sells"}},
		Events:  []string{"user.created"},
		Webhook: "/hooks", Setup: "/setup", Health: "/health", UI: "/",
	}
}

func signed(t *testing.T, m addon.Manifest, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	out, err := addon.Sign(raw, key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestASignatureCoversEveryFieldAndNothingElse: a signed manifest verifies
// however it is laid out, names the key that signed it, and stops verifying
// the moment any field — one the panel reads or one it does not — changes.
func TestASignatureCoversEveryFieldAndNothingElse(t *testing.T) {
	dev := addon.DevKey()
	raw := signed(t, sample(), addon.DevPrivateKey())
	key, err := addon.Verify(raw, []addon.Key{dev})
	if err != nil || key.Name != "development" {
		t.Fatalf("verify = %v, %v", key.Name, err)
	}

	// Re-laid out: compacted, keys in another order. Same content, same answer.
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	compact, _ := json.Marshal(doc)
	if _, err := addon.Verify(compact, []addon.Key{dev}); err != nil {
		t.Fatalf("a compacted copy no longer verifies: %v", err)
	}

	for name, edit := range map[string]func(map[string]any){
		"a scope widened": func(d map[string]any) {
			d["scopes"] = []any{map[string]any{"scope": "admins:write", "purpose": "x"}}
		},
		"the setup path moved":            func(d map[string]any) { d["setup"] = "/elsewhere" },
		"a field the panel does not read": func(d map[string]any) { d["homepage"] = "https://evil.example" },
	} {
		var d map[string]any
		_ = json.Unmarshal(raw, &d)
		edit(d)
		tampered, _ := json.Marshal(d)
		if _, err := addon.Verify(tampered, []addon.Key{dev}); !errors.Is(err, addon.ErrBadSignature) {
			t.Errorf("%s: %v, want a bad signature", name, err)
		}
	}

	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := addon.Verify(raw, []addon.Key{{Name: "other", Public: other}}); !errors.Is(err, addon.ErrBadSignature) {
		t.Fatalf("verified by a key that did not sign it: %v", err)
	}
	unsigned, _ := json.Marshal(sample())
	if _, err := addon.Verify(unsigned, []addon.Key{dev}); !errors.Is(err, addon.ErrUnsigned) {
		t.Fatalf("an unsigned manifest: %v", err)
	}
}

// TestManifestShape: what Parse refuses, each with its reason.
func TestManifestShape(t *testing.T) {
	if _, err := addon.Parse([]byte(`{"slug":"shop"}`)); err == nil || !strings.Contains(err.Error(), "api") {
		t.Fatalf("a manifest without api: %v", err)
	}
	for name, edit := range map[string]func(*addon.Manifest){
		"another api":           func(m *addon.Manifest) { m.API = 2 },
		"a bad slug":            func(m *addon.Manifest) { m.Slug = "Shop!" },
		"no name":               func(m *addon.Manifest) { m.Name = " " },
		"nothing asked":         func(m *addon.Manifest) { m.Scopes, m.Webhook, m.Events = nil, "", nil },
		"a webhook, no events":  func(m *addon.Manifest) { m.Events = nil },
		"events, no webhook":    func(m *addon.Manifest) { m.Webhook = "" },
		"no setup":              func(m *addon.Manifest) { m.Setup = "" },
		"an absolute setup":     func(m *addon.Manifest) { m.Setup = "https://elsewhere.example/setup" },
		"a climbing path":       func(m *addon.Manifest) { m.Health = "/a/../../etc" },
		"a scope without why":   func(m *addon.Manifest) { m.Scopes[0].Purpose = "" },
		"a scope twice":         func(m *addon.Manifest) { m.Scopes = append(m.Scopes, m.Scopes[0]) },
		"an event twice":        func(m *addon.Manifest) { m.Events = []string{"user.created", "user.created"} },
		"a ui that is not http": func(m *addon.Manifest) { m.UI = "javascript:alert(1)" },
	} {
		m := sample()
		m.Scopes = append([]addon.Scope(nil), m.Scopes...)
		edit(&m)
		raw, _ := json.Marshal(m)
		if _, err := addon.Parse(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	raw, _ := json.Marshal(sample())
	if _, err := addon.Parse(raw); err != nil {
		t.Fatalf("the sample: %v", err)
	}
}

// TestPathsStayUnderTheBase: an addon at a sub-path keeps it, and nothing a
// manifest names can leave it.
func TestPathsStayUnderTheBase(t *testing.T) {
	u, err := addon.NormalizeBase("https://apps.example.com/shop/")
	if err != nil || u.String() != "https://apps.example.com/shop" {
		t.Fatalf("normalize = %v, %v", u, err)
	}
	if got := addon.Join(u.String(), "/setup"); got != "https://apps.example.com/shop/setup" {
		t.Fatalf("join = %s", got)
	}
	for _, bad := range []string{"ftp://x", "https://user:pw@x", "https://x/?a=1", "x.example.com", "https://x/#f"} {
		if _, err := addon.NormalizeBase(bad); err == nil {
			t.Errorf("%s accepted as a base", bad)
		}
	}
	for _, bad := range []string{"setup", "//evil.example/x", "/a?b", "/a/../b", "/a b"} {
		if addon.ValidPath(bad) {
			t.Errorf("%q accepted as a path", bad)
		}
	}
}

// TestADuplicateKeyIsRefused: decoding into a map keeps the last of two
// equal keys and into a struct merges them, so a manifest that names a key
// twice — at any depth — is refused before it is parsed or verified: nothing
// can be added beside a signed field without breaking the signature.
func TestADuplicateKeyIsRefused(t *testing.T) {
	signed := `{"api":1,"slug":"s","name":"S","setup":"/setup","scopes":[{"scope":"users:read","purpose":"p"}],` +
		`"install":{"docker":{"image":"evil/img"}},"install":{"binary":{"linux-amd64":"s.tar.gz"}}}`
	if _, err := addon.Parse([]byte(signed)); err == nil || !strings.Contains(err.Error(), `"install" twice`) {
		t.Fatalf("Parse = %v", err)
	}
	if _, err := addon.SigningPayload([]byte(signed)); err == nil {
		t.Fatal("SigningPayload took a duplicate key")
	}
	nested := `{"api":1,"slug":"s","name":"S","setup":"/setup","scopes":[{"scope":"users:read","purpose":"p","purpose":"q"}]}`
	if _, err := addon.Parse([]byte(nested)); err == nil {
		t.Fatal("a duplicate inside an array's object passed")
	}
}

// TestPathsTheKitCannotServeAreRefused: a path with route syntax, or two of
// the manifest's paths on one route, would panic the addon's Mount.
func TestPathsTheKitCannotServeAreRefused(t *testing.T) {
	base := `{"api":1,"slug":"s","name":"S","scopes":[{"scope":"users:read","purpose":"p"}],"events":["user.created"],`
	for _, tail := range []string{
		`"setup":"/s/{a","webhook":"/hook"}`,
		`"setup":"/hook","webhook":"/hook"}`,
		`"setup":"/setup","webhook":"/hook","health":"/.well-known/nx-addon.json"}`,
	} {
		if _, err := addon.Parse([]byte(base + tail)); err == nil {
			t.Errorf("%s passed", tail)
		}
	}
}

// TestAPathMustBeCleanAndUnescaped: a route with an empty or "." segment can
// never match, and a %-escape is matched unescaped — so two different
// strings could be one route.
func TestAPathMustBeCleanAndUnescaped(t *testing.T) {
	for _, p := range []string{"/a//b", "/a/./b", "/a/.", "/hoo%6B", "/.well-known/nx-addon%2Ejson"} {
		if addon.ValidPath(p) {
			t.Errorf("ValidPath(%q) took it", p)
		}
	}
	for _, p := range []string{"/", "/a", "/a/b/", "/nx/setup"} {
		if !addon.ValidPath(p) {
			t.Errorf("ValidPath(%q) refused it", p)
		}
	}
	if _, err := addon.Parse([]byte(`{"api":1,"slug":`)); err == nil || !strings.Contains(err.Error(), "not a JSON object") || errors.Is(err, io.EOF) {
		t.Errorf("a truncated manifest = %v", err)
	}
}
