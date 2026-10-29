package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Key is a public key that signs manifests, and the name a consent screen
// gives whoever holds it.
type Key struct {
	Name   string
	Public ed25519.PublicKey
}

// nxKeyB64 verifies the manifests NX signs: its official addons.
// The private half never leaves NX. To rotate, a second key is added
// beside this one, the addons are re-signed, and the old one goes a release
// later.
const nxKeyB64 = "lWobXQl7JVIMNOAzngASRZg0hArCftGCmSLzmQpjjCM="

// NXKey is the key official addons are signed with.
func NXKey() Key {
	pub, err := base64.StdEncoding.DecodeString(nxKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		panic("manifest: bad embedded public key")
	}
	return Key{Name: "NX", Public: ed25519.PublicKey(pub)}
}

// ErrUnsigned is a manifest with no signature at all; ErrBadSignature one
// whose signature no trusted key made.
var (
	ErrUnsigned     = errors.New("the manifest is not signed; register the addon by hand instead")
	ErrBadSignature = errors.New("the manifest's signature was made by no key this panel trusts")
)

// SigningPayload is the exact bytes a signature covers: the manifest as a
// JSON object, its signature field taken out, re-encoded by encoding/json —
// keys sorted, no whitespace, numbers as written. Every field is covered,
// including ones this panel does not read, so nothing can be added to a
// signed manifest without breaking it; and the addon may serve it indented
// or reordered, since the payload is rebuilt from the content.
func SigningPayload(raw []byte) ([]byte, error) {
	if err := noDuplicateKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("the manifest is not a JSON object")
	}
	delete(doc, "signature")
	return json.Marshal(doc)
}

// Verify checks a manifest's signature against keys and names the key that
// made it.
func Verify(raw []byte, keys []Key) (Key, error) {
	var probe struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Key{}, errors.New("the manifest is not a JSON object")
	}
	if probe.Signature == "" {
		return Key{}, ErrUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(probe.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Key{}, ErrBadSignature
	}
	payload, err := SigningPayload(raw)
	if err != nil {
		return Key{}, err
	}
	for _, k := range keys {
		if ed25519.Verify(k.Public, payload, sig) {
			return k, nil
		}
	}
	return Key{}, ErrBadSignature
}

// Sign returns the manifest with its signature set, indented for serving.
// Used by the signing tools (cmd/nx-addon here, the panel's addonsign)
// and the test addons; a panel never signs.
func Sign(raw []byte, priv ed25519.PrivateKey) ([]byte, error) {
	payload, err := SigningPayload(raw)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	doc["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return json.MarshalIndent(doc, "", "  ")
}

// Digest is what the consent screen was shown, as a hash the registration
// sends back: the panel fetches the manifest again to register, and refuses
// when it is no longer the one the main admin approved.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// devSeed makes the development key: a key anyone can derive from this
// source, which is the point — it signs test addons, and only a panel built
// with -tags addondev trusts it, so no release accepts a manifest it signed.
var devSeed = sha256.Sum256([]byte("nx addon development key — trusted only by -tags addondev"))

// DevPrivateKey is the development key's private half.
func DevPrivateKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(devSeed[:]) }

// DevKey is the development key as a Key.
func DevKey() Key {
	return Key{Name: "development", Public: DevPrivateKey().Public().(ed25519.PublicKey)}
}
