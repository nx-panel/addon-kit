// Package addon is the running half of an NX addon: serving the manifest,
// taking the credentials the panel delivers at registration, receiving the
// panel's signed events, and answering the health check. An addon is a
// separate program that talks to the panel over the network only; this
// package is what every addon would otherwise write again.
//
//	raw, _ := os.ReadFile("nx-addon.json")
//	a, err := addon.New(addon.Config{Manifest: raw, DataDir: "data"})
//	a.OnEvent(func(e addon.Event) { … })
//	mux := http.NewServeMux()
//	a.Mount(mux)
//
// The install (by hand or by the panel) passes the claim code in
// NX_CLAIM_CODE and the answers to the manifest's install options in
// NX_OPT_<KEY>; FromEnv reads them.
package addon

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nx-panel/addon-kit/manifest"
)

// Config is how an addon is set up.
type Config struct {
	// Manifest is the addon's nx-addon.json, exactly as served (signed,
	// for an official or verified addon). Required.
	Manifest []byte
	// ClaimCode is the one-time code that lets the panel deliver the
	// credentials. Empty draws one and logs it, for an install done by hand.
	ClaimCode string
	// DataDir is where the credentials are kept (nx-credentials.json,
	// mode 0600). Empty keeps them in memory only, which a restart loses.
	DataDir string
	// Healthy answers the health check; nil is always healthy.
	Healthy func() error
	// Logf receives what happens; nil uses the standard logger.
	Logf func(format string, args ...any)
}

// FromEnv fills what the install passes in the environment: the claim code
// (NX_CLAIM_CODE) when the config has none.
func (c Config) FromEnv() Config {
	if c.ClaimCode == "" {
		c.ClaimCode = os.Getenv(manifest.EnvClaimCode)
	}
	return c
}

// Option is the answer the install gave to one of the manifest's install
// options, from NX_OPT_<KEY>; "" when it was not given.
func Option(key string) string { return os.Getenv(manifest.EnvName(key)) }

// PanelURL is the panel's address as the install gave it
// (NX_PANEL_URL); the credentials carry the one the panel saw itself.
func PanelURL() string { return os.Getenv(manifest.EnvPanelURL) }

// Credentials are what the panel delivered at registration.
type Credentials struct {
	API   int    `json:"api"`
	Panel Panel  `json:"panel"`
	Token string `json:"token,omitempty"`
	// Scopes the token holds.
	Scopes  []string `json:"scopes,omitempty"`
	Webhook *Webhook `json:"webhook,omitempty"`
	// ClaimedAt is when the addon accepted them.
	ClaimedAt time.Time `json:"claimedAt"`
}

// Panel is where the panel is.
type Panel struct {
	URL     string `json:"url"`
	Version string `json:"version"`
	// ID names the panel install, when the panel sends one.
	ID string `json:"id,omitempty"`
	// PublicURL is the address the operator gave the panel for people to
	// use (its public address, with its base path), when one is set. URL
	// is where the admin's browser reached the panel and is never shown to
	// an addon's customers.
	PublicURL string `json:"publicUrl,omitempty"`
}

// Webhook is the subscription the panel made for the addon.
type Webhook struct {
	ID     uint     `json:"id"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret"`
}

// Event is one delivery from the panel's event bus.
type Event struct {
	V          int             `json:"v"`
	ID         uint64          `json:"id"`
	Event      string          `json:"event"`
	Time       int64           `json:"time"`
	Data       json.RawMessage `json:"data"`
	Recipients []uint          `json:"recipients,omitempty"`
	// Delivery is X-Nx-Delivery: the same on every retry of this
	// delivery, which is what a receiver deduplicates on.
	Delivery string `json:"-"`
}

// Addon is a running addon's link to its panel.
type Addon struct {
	cfg      Config
	manifest manifest.Manifest
	claim    string

	// newInstall is whether this run was given another claim code than the
	// one the addon was registered with, not applied yet: a new install
	// over an earlier one's data.
	newInstall bool

	mu      sync.Mutex
	creds   *Credentials
	onEvent func(Event) error
	onSetup func(Credentials)
	seen    map[string]time.Time
	// running are the deliveries whose handler has not returned yet.
	running map[string]bool
}

// New checks the manifest and loads any credentials kept from an earlier run.
func New(cfg Config) (*Addon, error) {
	m, err := manifest.Parse(cfg.Manifest)
	if err != nil {
		return nil, fmt.Errorf("nx-addon.json: %w", err)
	}
	a := &Addon{cfg: cfg, manifest: m, claim: cfg.ClaimCode, seen: map[string]time.Time{}, running: map[string]bool{}}
	if a.cfg.Logf == nil {
		a.cfg.Logf = log.Printf
	}
	fresh, err := a.checkClaim()
	if err != nil {
		return nil, err
	}
	a.newInstall = fresh
	creds, err := a.load()
	if err != nil {
		return nil, err
	}
	if creds != nil && fresh {
		// The earlier install's registration: the panel that gave this
		// claim code holds none for this addon (it would not have issued
		// one), so the credentials are another registration's, and kept
		// they would refuse the new one as "already registered".
		if err := os.Remove(filepath.Join(a.cfg.DataDir, credentialsFile)); err != nil {
			return nil, err
		}
		a.cfg.Logf("nx: a new install (another claim code): the earlier registration with %s is dropped", creds.Panel.URL)
		creds = nil
	}
	if creds != nil {
		a.creds = creds
		return a, nil
	}
	if a.claim == "" {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		a.claim = strings.ToUpper(hex.EncodeToString(buf))
		a.cfg.Logf("nx: not registered yet — claim code %s", a.claim)
	}
	return a, nil
}

// Manifest is the parsed manifest.
func (a *Addon) Manifest() manifest.Manifest { return a.manifest }

// NewInstall is whether this run was given a claim code other than the one
// the addon was registered with: a new install over the data an earlier one
// left (removed without purging, then installed again). The earlier
// registration is dropped, so the new one can be made; the addon should
// apply the install's answers it otherwise uses only once, such as its
// first admin's password, then call NewInstallApplied. It stays so until
// then, or until the new install registers: a restart after either is not a
// new install again, which would undo what the admin did since. An update
// keeps the claim code, so it is never one; nor is the first run, or the
// first run of this kit over data an older one wrote.
func (a *Addon) NewInstall() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.newInstall
}

// NewInstallApplied records that the addon applied a new install's answers
// (NewInstall): the claim code is kept as this install's, so the next start
// is not a new install. Call it only once they are stored — a start that
// stops before keeps the new install for the next.
func (a *Addon) NewInstallApplied() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.newInstall {
		return nil
	}
	if err := a.recordClaim(); err != nil {
		return err
	}
	a.newInstall = false
	return nil
}

// ClaimCode is the code the panel must present, "" once registered.
func (a *Addon) ClaimCode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.creds != nil {
		return ""
	}
	return a.claim
}

// Credentials are the delivered credentials, nil before registration.
func (a *Addon) Credentials() *Credentials {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.creds == nil {
		return nil
	}
	c := *a.creds
	return &c
}

// OnEvent sets the function each verified event is handed to. It runs on the
// request; a slow handler delays the panel's next delivery to this addon.
// A handler that can fail should use OnEventErr instead.
func (a *Addon) OnEvent(f func(Event)) {
	if f == nil {
		a.OnEventErr(nil)
		return
	}
	a.OnEventErr(func(ev Event) error { f(ev); return nil })
}

// OnEventErr is OnEvent for a handler that can fail: an error (or a panic)
// answers the panel 500, so it delivers the event again, and the delivery
// is not taken for a repeat when it does. The seen set lives in memory, so
// a delivery retried across the addon's restart is handed on again: a
// handler keeps its own effects idempotent.
func (a *Addon) OnEventErr(f func(Event) error) {
	a.mu.Lock()
	a.onEvent = f
	a.mu.Unlock()
}

// OnSetup sets the function called once the credentials have arrived.
func (a *Addon) OnSetup(f func(Credentials)) {
	a.mu.Lock()
	a.onSetup = f
	a.mu.Unlock()
}

// Mount puts the manifest, setup, webhook and health paths on mux.
func (a *Addon) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET "+manifest.WellKnownPath, a.serveManifest)
	mux.HandleFunc("POST "+a.manifest.Setup, a.handleSetup)
	if a.manifest.Webhook != "" {
		mux.HandleFunc("POST "+a.manifest.Webhook, a.handleEvent)
	}
	if a.manifest.Health != "" {
		mux.HandleFunc("GET "+a.manifest.Health, a.handleHealth)
	}
}

func (a *Addon) serveManifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(a.cfg.Manifest)
}

func (a *Addon) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if a.cfg.Healthy != nil {
		if err := a.cfg.Healthy(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// handleSetup takes the credentials, once, and only with the claim code.
func (a *Addon) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req manifest.SetupRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	if a.creds != nil {
		a.mu.Unlock()
		http.Error(w, "already registered", http.StatusConflict)
		return
	}
	if a.claim == "" || !hmac.Equal([]byte(req.ClaimCode), []byte(a.claim)) {
		a.mu.Unlock()
		a.cfg.Logf("nx: setup refused: wrong claim code")
		http.Error(w, "wrong claim code", http.StatusForbidden)
		return
	}
	creds := &Credentials{
		API: req.API, Panel: Panel{URL: req.Panel.URL, Version: req.Panel.Version, ID: req.Panel.ID, PublicURL: req.Panel.PublicURL},
		Token: req.Token, Scopes: req.Scopes, ClaimedAt: time.Now().UTC(),
	}
	if req.Webhook != nil {
		creds.Webhook = &Webhook{ID: req.Webhook.ID, URL: req.Webhook.URL, Events: req.Webhook.Events, Secret: req.Webhook.Secret}
	}
	if err := a.save(creds); err != nil {
		a.mu.Unlock()
		a.cfg.Logf("nx: keeping the credentials failed: %v", err)
		http.Error(w, "could not keep the credentials", http.StatusInternalServerError)
		return
	}
	a.creds = creds
	a.newInstall = false
	if err := a.recordClaim(); err != nil {
		a.cfg.Logf("nx: keeping the claim code's record failed: %v", err)
	}
	onSetup := a.onSetup
	a.mu.Unlock()
	a.cfg.Logf("nx: registered with %s (panel %s)", creds.Panel.URL, creds.Panel.Version)
	if onSetup != nil {
		onSetup(*creds)
	}
	w.WriteHeader(http.StatusNoContent)
}

// MaxSkew is how old a delivery's signed timestamp may be.
const MaxSkew = 5 * time.Minute

// handleEvent hands on a delivery whose signature the webhook secret
// verifies, once per X-Nx-Delivery.
func (a *Addon) handleEvent(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	creds, onEvent := a.creds, a.onEvent
	a.mu.Unlock()
	if creds == nil || creds.Webhook == nil {
		http.Error(w, "not registered", http.StatusServiceUnavailable)
		return
	}
	if err := VerifySignature(creds.Webhook.Secret, r.Header.Get("X-Nx-Signature"), body, time.Now(), MaxSkew); err != nil {
		a.cfg.Logf("nx: delivery refused: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	ev.Delivery = r.Header.Get("X-Nx-Delivery")
	if ev.Delivery != "" {
		switch a.claimDelivery(ev.Delivery) {
		case deliveryDone:
			w.WriteHeader(http.StatusNoContent)
			return
		case deliveryRunning:
			// The first attempt is still being handled and may yet fail:
			// this retry is not taken either, so the panel tries again.
			http.Error(w, "still being handled; try again", http.StatusServiceUnavailable)
			return
		}
	}
	err = a.dispatch(onEvent, ev)
	if ev.Delivery != "" {
		a.finishDelivery(ev.Delivery, err == nil)
	}
	if err != nil {
		// Not taken: the panel retries it, and the retry is not a repeat.
		a.cfg.Logf("nx: event %s (delivery %s) not taken: %v", ev.Event, ev.Delivery, err)
		http.Error(w, "not taken; try again", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// dispatch hands an event on, turning a panic into an error so the
// delivery is retried rather than lost.
func (a *Addon) dispatch(f func(Event) error, ev Event) (err error) {
	if f == nil {
		return nil
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("the handler panicked: %v", p)
		}
	}()
	return f(ev)
}

// What claimDelivery found.
const (
	deliveryNew = iota
	deliveryRunning
	deliveryDone
)

// claimDelivery marks a delivery as being handled, unless it is being
// handled already or was handled within the skew window — a retry the addon
// answered but the panel did not hear.
func (a *Addon) claimDelivery(id string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running[id] {
		return deliveryRunning
	}
	now := time.Now()
	for k, at := range a.seen {
		if now.Sub(at) > 2*MaxSkew {
			delete(a.seen, k)
		}
	}
	if _, ok := a.seen[id]; ok {
		return deliveryDone
	}
	a.running[id] = true
	return deliveryNew
}

// finishDelivery records how a claimed delivery ended: taken, it is seen;
// not taken, the panel's retry of it is handled afresh.
func (a *Addon) finishDelivery(id string, taken bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.running, id)
	if taken {
		a.seen[id] = time.Now()
	}
}

const credentialsFile = "nx-credentials.json"

// claimFile keeps a hash of the claim code the addon was registered with.
const claimFile = "nx-claim"

// checkClaim reports whether the claim code this run was given differs
// from the one recorded: a new install. The record is the claim code the
// addon was last registered with (recordClaim); with none — the first run,
// or data an older kit wrote — this run's is recorded, and it is not one.
// Until the new install registers, every run is it: a restart before then
// still drops nothing it should keep and applies the same answers again.
func (a *Addon) checkClaim() (bool, error) {
	if a.cfg.ClaimCode == "" || a.cfg.DataDir == "" {
		return false, nil
	}
	prev, err := os.ReadFile(filepath.Join(a.cfg.DataDir, claimFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	was := strings.TrimSpace(string(prev))
	if was == "" {
		return false, a.recordClaim()
	}
	return was != claimHash(a.cfg.ClaimCode), nil
}

// recordClaim keeps a hash of the claim code the install gave.
func (a *Addon) recordClaim() error {
	if a.cfg.ClaimCode == "" || a.cfg.DataDir == "" {
		return nil
	}
	if err := os.MkdirAll(a.cfg.DataDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.cfg.DataDir, claimFile), []byte(claimHash(a.cfg.ClaimCode)+"\n"), 0o600)
}

func claimHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func (a *Addon) load() (*Credentials, error) {
	if a.cfg.DataDir == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(a.cfg.DataDir, credentialsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", credentialsFile, err)
	}
	return &c, nil
}

func (a *Addon) save(c *Credentials) error {
	if a.cfg.DataDir == "" {
		return nil
	}
	if err := os.MkdirAll(a.cfg.DataDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(a.cfg.DataDir, credentialsFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(a.cfg.DataDir, credentialsFile))
}

// Forget drops the credentials — after panel.addon_removed, say — so the
// addon can be registered again with a new claim code.
func (a *Addon) Forget() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.creds = nil
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	a.claim = strings.ToUpper(hex.EncodeToString(buf))
	a.cfg.Logf("nx: credentials dropped — new claim code %s", a.claim)
	if a.cfg.DataDir == "" {
		return nil
	}
	err := os.Remove(filepath.Join(a.cfg.DataDir, credentialsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
