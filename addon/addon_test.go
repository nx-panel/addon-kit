package addon_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nx-panel/addon-kit/addon"
	"github.com/nx-panel/addon-kit/manifest"
)

const testManifest = `{"api": 1, "slug": "demo", "name": "Demo", "version": "0.1.0", "publisher": "x",
  "scopes": [{"scope": "users:read", "purpose": "list"}], "events": ["user.created"],
  "webhook": "/nx/events", "setup": "/nx/setup", "health": "/health"}`

func start(t *testing.T, dir string, healthy func() error) (*addon.Addon, *httptest.Server) {
	t.Helper()
	a, err := addon.New(addon.Config{Manifest: []byte(testManifest), ClaimCode: "CODE-1", DataDir: dir, Healthy: healthy, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return a, srv
}

func post(t *testing.T, url string, body any, header map[string]string) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func setupBody(code string) manifest.SetupRequest {
	return manifest.SetupRequest{
		API: 1, ClaimCode: code, Panel: manifest.SetupPanel{URL: "https://panel.example", Version: "0.1.0"},
		Token: "tok", Scopes: []string{"users:read"},
		Webhook: &manifest.SetupWebhook{ID: 7, URL: "https://addon/nx/events", Events: []string{"user.created"}, Secret: "s3cret"},
	}
}

func TestTheCredentialsArriveOnceWithTheClaimCodeAndSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	a, srv := start(t, dir, nil)
	if code := post(t, srv.URL+"/nx/setup", setupBody("WRONG"), nil); code != http.StatusForbidden {
		t.Fatalf("wrong code = %d", code)
	}
	if a.Credentials() != nil {
		t.Fatal("a wrong code delivered credentials")
	}
	if code := post(t, srv.URL+"/nx/setup", setupBody("CODE-1"), nil); code != http.StatusNoContent {
		t.Fatalf("right code = %d", code)
	}
	if code := post(t, srv.URL+"/nx/setup", setupBody("CODE-1"), nil); code != http.StatusConflict {
		t.Fatalf("second setup = %d", code)
	}
	again, err := addon.New(addon.Config{Manifest: []byte(testManifest), DataDir: dir, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if c := again.Credentials(); c == nil || c.Token != "tok" || c.Webhook.Secret != "s3cret" || again.ClaimCode() != "" {
		t.Fatalf("after a restart: %+v", c)
	}
}

// An addon removed without its data and installed again gets a new claim
// code: the earlier registration is dropped, so the panel that issued the
// code can register it, and the addon is told it is a new install. A
// restart or an update keeps the claim code, and with it the registration.
func TestANewClaimCodeIsANewInstall(t *testing.T) {
	dir := t.TempDir()
	open := func(code string) *addon.Addon {
		t.Helper()
		a, err := addon.New(addon.Config{Manifest: []byte(testManifest), ClaimCode: code, DataDir: dir, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a, srv := start(t, dir, nil)
	if a.NewInstall() {
		t.Fatal("the first run is a new install over nothing")
	}
	if code := post(t, srv.URL+"/nx/setup", setupBody("CODE-1"), nil); code != http.StatusNoContent {
		t.Fatalf("setup = %d", code)
	}
	if again := open("CODE-1"); again.NewInstall() || again.Credentials() == nil {
		t.Fatalf("a restart with the same code: new=%v, credentials %v", again.NewInstall(), again.Credentials())
	}
	fresh := open("CODE-2")
	if !fresh.NewInstall() || fresh.Credentials() != nil || fresh.ClaimCode() != "CODE-2" {
		t.Fatalf("another code: new=%v, credentials %v, claim %q", fresh.NewInstall(), fresh.Credentials(), fresh.ClaimCode())
	}
	// A restart before the addon applied it is still the new install.
	again := open("CODE-2")
	if !again.NewInstall() || again.Credentials() != nil {
		t.Fatalf("restarted before applying: new=%v, credentials %v", again.NewInstall(), again.Credentials())
	}
	// Applied, a restart before it registers is not: what the admin
	// changed since stays; it still registers by the new code.
	if err := again.NewInstallApplied(); err != nil || again.NewInstall() {
		t.Fatalf("applied: %v, new=%v", err, again.NewInstall())
	}
	if again := open("CODE-2"); again.NewInstall() || again.Credentials() != nil || again.ClaimCode() != "CODE-2" {
		t.Fatalf("restarted before registering: new=%v, credentials %v, claim %q", again.NewInstall(), again.Credentials(), again.ClaimCode())
	}
	mux := http.NewServeMux()
	fresh.Mount(mux)
	srv2 := httptest.NewServer(mux)
	defer srv2.Close()
	if code := post(t, srv2.URL+"/nx/setup", setupBody("CODE-2"), nil); code != http.StatusNoContent {
		t.Fatalf("the new install's registration = %d", code)
	}
	if fresh.NewInstall() {
		t.Fatal("still a new install once registered")
	}
	if after := open("CODE-2"); after.NewInstall() || after.Credentials() == nil {
		t.Fatalf("its restart: new=%v, credentials %v", after.NewInstall(), after.Credentials())
	}
	// Data an older kit wrote has no record: its claim code is taken as
	// the one it was installed with.
	if err := os.Remove(filepath.Join(dir, "nx-claim")); err != nil {
		t.Fatal(err)
	}
	if older := open("CODE-3"); older.NewInstall() || older.Credentials() == nil {
		t.Fatalf("over an older kit's data: new=%v, credentials %v", older.NewInstall(), older.Credentials())
	}
}

func TestOnlySignedFreshDeliveriesReachTheAddonOnce(t *testing.T) {
	a, srv := start(t, "", nil)
	post(t, srv.URL+"/nx/setup", setupBody("CODE-1"), nil)
	var got []addon.Event
	a.OnEvent(func(e addon.Event) { got = append(got, e) })

	body := []byte(`{"v":1,"id":3,"event":"user.created","time":1,"data":{"userId":1}}`)
	send := func(secret string, at time.Time, delivery string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/nx/events", bytes.NewReader(body))
		req.Header.Set("X-Nx-Signature", addon.Sign(secret, at.Unix(), body))
		req.Header.Set("X-Nx-Delivery", delivery)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := send("other", time.Now(), "1"); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret = %d", code)
	}
	if code := send("s3cret", time.Now().Add(-10*time.Minute), "1"); code != http.StatusUnauthorized {
		t.Fatalf("stale = %d", code)
	}
	for range 2 {
		if code := send("s3cret", time.Now(), "9"); code != http.StatusNoContent {
			t.Fatalf("good = %d", code)
		}
	}
	if len(got) != 1 || got[0].Event != "user.created" || got[0].ID != 3 || got[0].Delivery != "9" {
		t.Fatalf("handed on %+v, want one user.created", got)
	}
}

func TestHealthAnswersWhatTheAddonSays(t *testing.T) {
	var broken error
	_, srv := start(t, "", func() error { return broken })
	for _, c := range []struct {
		err  error
		want int
	}{{nil, http.StatusOK}, {errors.New("db down"), http.StatusServiceUnavailable}} {
		broken = c.err
		resp, err := http.Get(srv.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Fatalf("health with %v = %d, want %d", c.err, resp.StatusCode, c.want)
		}
	}
	resp, _ := http.Get(srv.URL + manifest.WellKnownPath)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOptionsComeFromTheEnvironment(t *testing.T) {
	t.Setenv("NX_OPT_DATABASE", "postgres")
	t.Setenv("NX_CLAIM_CODE", "FROM-ENV")
	if got := addon.Option("database"); got != "postgres" {
		t.Fatalf("Option = %q", got)
	}
	a, err := addon.New(addon.Config{Manifest: []byte(testManifest), Logf: t.Logf}.FromEnv())
	if err != nil {
		t.Fatal(err)
	}
	if a.ClaimCode() != "FROM-ENV" {
		t.Fatalf("claim code = %q", a.ClaimCode())
	}
}

// TestAnEventNotTakenIsDeliveredAgain: a handler that fails — or panics —
// answers 500, and the panel's retry of the same delivery reaches it again
// instead of being dropped as a repeat; the panel's public address arrives
// with the credentials.
func TestAnEventNotTakenIsDeliveredAgain(t *testing.T) {
	a, srv := start(t, "", nil)
	body := setupBody("CODE-1")
	body.Panel.PublicURL = "https://vpn.example/sub"
	post(t, srv.URL+"/nx/setup", body, nil)
	if c := a.Credentials(); c == nil || c.Panel.PublicURL != "https://vpn.example/sub" {
		t.Fatalf("the public address was not kept: %+v", c)
	}
	calls := 0
	a.OnEventErr(func(addon.Event) error {
		calls++
		switch calls {
		case 1:
			return errors.New("the database is busy")
		case 2:
			panic("a bug")
		}
		return nil
	})
	ev := []byte(`{"v":1,"id":4,"event":"user.created","time":1,"data":{}}`)
	send := func() int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/nx/events", bytes.NewReader(ev))
		req.Header.Set("X-Nx-Signature", addon.Sign("s3cret", time.Now().Unix(), ev))
		req.Header.Set("X-Nx-Delivery", "42")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i, want := range []int{http.StatusInternalServerError, http.StatusInternalServerError, http.StatusNoContent, http.StatusNoContent} {
		if code := send(); code != want {
			t.Fatalf("delivery %d = %d, want %d", i+1, code, want)
		}
	}
	if calls != 3 {
		t.Fatalf("the handler ran %d times, want 3 (the last send is a repeat)", calls)
	}
}

// TestARetryWhileTheFirstAttemptRunsIsNotTaken: the panel gives up on an
// attempt after seconds and retries; while the first is still handled the
// retry is answered 503, so if the first then fails the event is not lost.
func TestARetryWhileTheFirstAttemptRunsIsNotTaken(t *testing.T) {
	a, srv := start(t, "", nil)
	post(t, srv.URL+"/nx/setup", setupBody("CODE-1"), nil)
	release := make(chan struct{})
	started := make(chan struct{})
	calls := 0
	a.OnEventErr(func(addon.Event) error {
		calls++
		if calls == 1 {
			close(started)
			<-release
			return errors.New("the database is busy")
		}
		return nil
	})
	ev := []byte(`{"v":1,"id":5,"event":"user.created","time":1,"data":{}}`)
	send := func() int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/nx/events", bytes.NewReader(ev))
		req.Header.Set("X-Nx-Signature", addon.Sign("s3cret", time.Now().Unix(), ev))
		req.Header.Set("X-Nx-Delivery", "77")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	first := make(chan int)
	go func() { first <- send() }()
	<-started
	if code := send(); code != http.StatusServiceUnavailable {
		t.Fatalf("a retry while the first runs = %d, want 503", code)
	}
	close(release)
	if code := <-first; code != http.StatusInternalServerError {
		t.Fatalf("the first attempt = %d, want 500", code)
	}
	if code := send(); code != http.StatusNoContent || calls != 2 {
		t.Fatalf("the next retry = %d after %d calls, want 204 after 2", code, calls)
	}
}
