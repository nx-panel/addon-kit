package addon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The certificate the panel holds for this addon (the panel's
// docs/phase-h.md H-S2): the main admin chooses it, the panel issues and
// renews it, and the addon fetches it — by its token once registered, by its
// claim code before, since the panel reads the manifest over https at the
// registration. web.TLS in the https mode "panel" asks for it through
// PanelCertificate.

// certPaths are where the panel answers, under its /api/v1.
const (
	certPath      = "/api/v1/addons/self/certificate"
	certClaimPath = "/api/v1/addons/self/certificate/claim"
)

// certClient is how the panel is asked; a test may replace it.
var certClient = &http.Client{Timeout: 30 * time.Second}

// PanelCertificate fetches the certificate the panel holds for this addon,
// as web.CertSource asks: have is the hex SHA-256 of the leaf held now, and
// a certificate still the same comes back as nil PEM and no error. Before
// registration it asks with the claim code, at the panel address the install
// gave (NX_PANEL_URL); after, with the token at the address the
// credentials carry.
func (a *Addon) PanelCertificate(ctx context.Context, have string) (certPEM, keyPEM []byte, err error) {
	a.mu.Lock()
	creds, claim := a.creds, a.claim
	a.mu.Unlock()
	var req *http.Request
	if creds != nil {
		base := strings.TrimRight(creds.Panel.URL, "/")
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+certPath, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+creds.Token)
	} else {
		base := strings.TrimRight(PanelURL(), "/")
		if base == "" || claim == "" {
			return nil, nil, errors.New("not registered, and the install gave no panel address and claim code to ask with")
		}
		body, _ := json.Marshal(map[string]string{"slug": a.manifest.Slug, "claimCode": claim})
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, base+certClaimPath, bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	}
	if have != "" {
		req.Header.Set("If-None-Match", `"`+have+`"`)
	}
	resp, err := certClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, nil, nil
	default:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return nil, nil, fmt.Errorf("the panel answered %d: %s", resp.StatusCode, e.Error)
	}
	var c struct {
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Certificate == "" || c.Key == "" {
		return nil, nil, errors.New("the panel's answer carries no certificate")
	}
	return []byte(c.Certificate), []byte(c.Key), nil
}
