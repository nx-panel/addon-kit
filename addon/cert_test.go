package addon_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nx-panel/addon-kit/addon"
	"github.com/nx-panel/addon-kit/manifest"
	"github.com/nx-panel/addon-kit/web"
)

// An addon is where web.TLS gets the panel's certificate from.
var _ web.CertSource = (*addon.Addon)(nil)

// TestTheCertificateIsFetchedByClaimCodeThenByToken: before registration the
// addon asks with its claim code at the address the install gave; after, with
// its token at the address the credentials carry; what it holds is a 304.
func TestTheCertificateIsFetchedByClaimCodeThenByToken(t *testing.T) {
	var seen []string
	panelMux := http.NewServeMux()
	panelMux.HandleFunc("POST /api/v1/addons/self/certificate/claim", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, "claim "+body["slug"]+" "+body["claimCode"])
		if body["claimCode"] != "CODE-1" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"no install waits with this claim code"}`))
			return
		}
		_, _ = w.Write([]byte(`{"certificate":"CERT","key":"KEY","sha256":"abc"}`))
	})
	panelMux.HandleFunc("GET /api/v1/addons/self/certificate", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "token "+r.Header.Get("Authorization")+" "+r.Header.Get("If-None-Match"))
		if r.Header.Get("If-None-Match") == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(`{"certificate":"CERT2","key":"KEY2","sha256":"def"}`))
	})
	panel := httptest.NewServer(panelMux)
	defer panel.Close()
	t.Setenv(manifest.EnvPanelURL, panel.URL+"/")

	a, srv := start(t, t.TempDir(), nil)
	cert, key, err := a.PanelCertificate(context.Background(), "")
	if err != nil || string(cert) != "CERT" || string(key) != "KEY" {
		t.Fatalf("by claim code = %q %q %v", cert, key, err)
	}

	body := setupBody("CODE-1")
	body.Panel.URL = panel.URL
	if code := post(t, srv.URL+"/nx/setup", body, nil); code != http.StatusNoContent {
		t.Fatalf("setup = %d", code)
	}
	if cert, _, err := a.PanelCertificate(context.Background(), "abc"); err != nil || cert != nil {
		t.Fatalf("an unchanged certificate = %q %v", cert, err)
	}
	if cert, _, err := a.PanelCertificate(context.Background(), "old"); err != nil || string(cert) != "CERT2" {
		t.Fatalf("a newer one = %q %v", cert, err)
	}
	if got := strings.Join(seen, "|"); got != `claim demo CODE-1|token Bearer tok "abc"|token Bearer tok "old"` {
		t.Fatalf("the panel saw %s", got)
	}

	// A wrong code is the panel's error, said.
	other, err := addon.New(addon.Config{Manifest: []byte(testManifest), ClaimCode: "WRONG", Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.PanelCertificate(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a wrong claim code = %v", err)
	}
}
