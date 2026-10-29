package manifest_test

import (
	"encoding/json"
	"strings"
	"testing"

	addon "github.com/nx-panel/addon-kit/manifest"
)

// A v1 manifest as an addon's repository root carries it:
// every option type, a conditional option, both install shapes.
const v1Manifest = `{
  "api": 1, "slug": "shop", "name": "NX Shop", "version": "1.0.0",
  "publisher": "NX", "license": "proprietary", "paid": false,
  "description": {"en": "Sell and renew accounts", "fa": "فروش و تمدید حساب"},
  "docs": "https://addons.nx-panel.org/shop",
  "requires": {"panel": ">=0.1.0"},
  "install": {
    "docker": {"image": "ghcr.io/nx-panel/shop", "compose": "deploy/compose.yml"},
    "binary": {"linux-amd64": "shop-linux-amd64.tar.gz", "linux-arm64": "shop-linux-arm64.tar.gz"},
    "options": [
      {"key": "port", "type": "port", "default": 8090, "label": {"en": "Port", "fa": "پورت"}},
      {"key": "database", "type": "choice", "choices": ["sqlite", "postgres"], "default": "sqlite", "label": {"en": "Database"}},
      {"key": "database_dsn", "type": "secret", "required": true, "when": {"database": "postgres"}, "label": {"en": "PostgreSQL DSN"}},
      {"key": "public_url", "type": "url", "required": true, "label": {"en": "Public address"}},
      {"key": "bot_name", "type": "string", "label": {"en": "Bot name"}, "help": {"en": "Shown to customers"}},
      {"key": "trial_days", "type": "number", "default": 1, "label": {"en": "Trial days"}},
      {"key": "trials", "type": "bool", "default": true, "label": {"en": "Offer trials"}},
      {"key": "trial_volume", "type": "number", "when": {"trials": "true"}, "label": {"en": "Trial volume (GB)"}},
      {"key": "base_path", "type": "path", "label": {"en": "Admin path"}},
      {"key": "admin_password", "type": "password", "required": true, "label": {"en": "Admin password"}}
    ]
  },
  "scopes": [{"scope": "users:write", "purpose": "to create the accounts it sells"}],
  "rateLimit": 300,
  "setup": "/nx/setup", "health": "/health", "ui": "/"
}`

func TestAV1ManifestWithEveryOptionTypeParses(t *testing.T) {
	m, err := addon.Parse([]byte(v1Manifest))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.API != 1 || m.Install == nil || len(m.Install.Options) != 10 || m.Install.Docker.Image != "ghcr.io/nx-panel/shop" || m.RateLimit != 300 {
		t.Fatalf("manifest = %+v", m)
	}
	if got := addon.EnvName("database_dsn"); got != "NX_OPT_DATABASE_DSN" {
		t.Fatalf("EnvName = %q", got)
	}
}

// Each broken variant is refused, and the error names the field, so an
// addon's author can find it.
func TestAMalformedV1ManifestNamesTheField(t *testing.T) {
	cases := []struct {
		name, from, to, want string
	}{
		{"unknown type", `"type": "string"`, `"type": "text"`, "install.options.bot_name: type"},
		{"no english label", `"label": {"en": "Port", "fa": "پورت"}`, `"label": {"fa": "پورت"}`, "install.options.port.label"},
		{"secret default", `"type": "secret", "required": true`, `"type": "secret", "default": "x", "required": true`, "a secret has no default"},
		{"default outside choices", `"default": "sqlite"`, `"default": "mysql"`, "install.options.database.default"},
		{"when on a later option", `"when": {"database": "postgres"}`, `"when": {"public_url": "x"}`, "not an option declared before it"},
		{"when value not a choice", `"when": {"database": "postgres"}`, `"when": {"database": "mysql"}`, "is not one of database's choices"},
		{"bad port default", `"default": 8090`, `"default": 70000`, "port from 1 to 65535"},
		{"tagged image", `"ghcr.io/nx-panel/shop"`, `"ghcr.io/nx-panel/shop:1.0.0"`, "install.docker.image"},
		{"compose escapes", `"deploy/compose.yml"`, `"../compose.yml"`, "install.docker.compose"},
		{"unknown platform", `"linux-arm64"`, `"windows-amd64"`, "install.binary"},
		{"bad requires", `">=0.1.0"`, `"^0.1"`, "requires.panel"},
		{"unknown language", `"fa": "فروش و تمدید حساب"`, `"de": "Verkauf"`, "description"},
		{"duplicate key", `"key": "trial_days"`, `"key": "port"`, "install.options.port is declared twice"},
		{"api 2", `"api": 1`, `"api": 2`, "api 2"},
		{"rate limit past the ceiling", `"rateLimit": 300`, `"rateLimit": 601`, "rateLimit"},
		{"negative rate limit", `"rateLimit": 300`, `"rateLimit": -1`, "rateLimit"},
		{"two paths", `"key": "bot_name", "type": "string"`, `"key": "bot_name", "type": "path"`, "at most one path option"},
		{"bad path default", `"type": "path", "label"`, `"type": "path", "default": "a/b", "label"`, "install.options.base_path.default"},
		{"password default", `"type": "password", "required": true`, `"type": "password", "default": "long-enough-1", "required": true`, "a password has no default"},
	}
	for _, c := range cases {
		raw := strings.Replace(v1Manifest, c.from, c.to, 1)
		if raw == v1Manifest {
			t.Fatalf("%s: the replacement did not apply", c.name)
		}
		_, err := addon.Parse([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", c.name, err, c.want)
		}
	}
}

// An api 0 manifest is Phase F's and stays valid; it may not borrow api 1's
// fields, which an api 0 panel would not have read.
func TestAnAPI0ManifestStaysValidAndStaysV0(t *testing.T) {
	v0 := `{"api": 0, "slug": "old", "name": "Old", "version": "0.1.0", "publisher": "x",
	        "scopes": [{"scope": "users:read", "purpose": "list"}], "setup": "/setup"}`
	if _, err := addon.Parse([]byte(v0)); err != nil {
		t.Fatalf("api 0: %v", err)
	}
	mixed := strings.Replace(v0, `"setup": "/setup"`, `"setup": "/setup", "install": {"binary": {"linux-amd64": "a.tgz"}}`, 1)
	if _, err := addon.Parse([]byte(mixed)); err == nil || !strings.Contains(err.Error(), "api 1 fields") {
		t.Fatalf("api 0 with an install section: %v", err)
	}
	rated := strings.Replace(v0, `"setup": "/setup"`, `"setup": "/setup", "rateLimit": 300`, 1)
	if _, err := addon.Parse([]byte(rated)); err == nil || !strings.Contains(err.Error(), "api 1 fields") {
		t.Fatalf("api 0 with a rate limit: %v", err)
	}
}

func TestRequiresPanel(t *testing.T) {
	m, err := addon.Parse([]byte(strings.Replace(v1Manifest, `">=0.1.0"`, `">=0.2.0"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	for version, want := range map[string]bool{"0.1.9": false, "0.2.0": true, "v0.3.1": true, "dev": true, "": true} {
		if got := m.SatisfiesPanel(version); got != want {
			t.Errorf("panel %q satisfies >=0.2.0 = %v, want %v", version, got, want)
		}
	}
}

func TestAnswersAreCheckedByType(t *testing.T) {
	m, _ := addon.Parse([]byte(v1Manifest))
	opt := map[string]addon.Option{}
	for _, o := range m.Install.Options {
		opt[o.Key] = o
	}
	for _, c := range []struct {
		key, answer string
		ok          bool
	}{
		{"port", `443`, true},
		{"port", `0`, false},
		{"port", `"443"`, false},
		{"database", `"postgres"`, true},
		{"database", `"mysql"`, false},
		{"public_url", `"https://shop.example.com"`, true},
		{"public_url", `"shop.example.com"`, false},
		{"trials", `false`, true},
		{"trials", `"no"`, false},
		{"trial_days", `2.5`, true},
		{"trial_days", `"two"`, false},
		{"base_path", `"x9k2"`, true},
		{"base_path", `"/x9k2/"`, true},
		{"base_path", `""`, true},
		{"base_path", `"a/b"`, false},
		{"base_path", `"../x"`, false},
		{"base_path", `"a b"`, false},
		// A password option holds the install's answer to the rule the
		// addon's sign-in holds a password to.
		{"admin_password", `"ten-chars!"`, true},
		{"admin_password", `"short"`, false},
		{"admin_password", `"گذرواژه‌ی۱"`, true},
		{"admin_password", `"` + strings.Repeat("ر", 37) + `"`, false},
		{"admin_password", `""`, true},
	} {
		err := addon.CheckAnswer(opt[c.key], json.RawMessage(c.answer))
		if (err == nil) != c.ok {
			t.Errorf("%s = %s: err %v, want ok=%v", c.key, c.answer, err, c.ok)
		}
	}
}

func TestABasePathIsOneSegmentOrTheRoot(t *testing.T) {
	for in, want := range map[string]string{"": "", "/": "", "admin": "/admin", "/admin/": "/admin", " x_9-Z ": "/x_9-Z"} {
		got, err := addon.NormalizeBasePath(in)
		if err != nil || got != want {
			t.Errorf("NormalizeBasePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"a/b", "-x", "x.y", strings.Repeat("a", 65), "%2e"} {
		if _, err := addon.NormalizeBasePath(in); err == nil {
			t.Errorf("NormalizeBasePath(%q) took it", in)
		}
	}
}
