package addon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// VerifySignature checks a delivery's X-Nx-Signature the way the panel
// signs it: `t=<unix>,v1=<hex>`, the hex being HMAC-SHA256(secret,
// "<t>.<body>"). The timestamp is inside the MAC, so refusing one older than
// maxSkew refuses a captured delivery replayed later.
func VerifySignature(secret, header string, body []byte, now time.Time, maxSkew time.Duration) error {
	var t, v1 string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			t = v
		case "v1":
			v1 = v
		}
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil || v1 == "" {
		return errors.New("malformed signature")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > maxSkew || d < -maxSkew {
		return errors.New("signature timestamp outside the allowed skew")
	}
	if !hmac.Equal([]byte(Sign(secret, ts, body)), []byte("t="+t+",v1="+v1)) {
		return errors.New("signature mismatch")
	}
	return nil
}

// Sign is the panel's half, for tests that play the panel.
func Sign(secret string, t int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(t, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + strconv.FormatInt(t, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}
