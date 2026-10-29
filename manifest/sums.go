package manifest

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// A release's checksums and their signature (docs/phase-g.md P45 (b′)):
// SHA256SUMS lists every asset — the binaries and install.sh among them —
// as sha256sum writes it, and SHA256SUMS.sig is the developer's signature
// over it with the key that signs the manifest. The manifest cannot pin the
// binaries itself: an addon embeds its manifest in its binary, so a digest
// of the binary cannot be inside it. The panel runs a release's install.sh,
// or installs its binary, only when both match a SHA256SUMS signed by the
// key that signed the release's manifest.
const (
	SumsFile    = "SHA256SUMS"
	SumsSigFile = "SHA256SUMS.sig"
	// InstallScript is the name install.sh is listed under.
	InstallScript = "install.sh"
)

// sumsDomain keeps a checksums signature from ever passing for a
// manifest's, or the other way round: the bytes signed begin with it.
const sumsDomain = "nx-addon SHA256SUMS v1\n"

// ErrSumsUnsigned is a release with no SHA256SUMS.sig; ErrSumsBadSignature
// one whose signature the manifest's key did not make.
var (
	ErrSumsUnsigned     = errors.New("the release's SHA256SUMS is not signed (no SHA256SUMS.sig)")
	ErrSumsBadSignature = errors.New("the release's SHA256SUMS.sig was not made by the key that signed its manifest")
)

func sumsPayload(sums []byte) []byte {
	return append([]byte(sumsDomain), sums...)
}

// SignSums is SHA256SUMS.sig for sums: the base64 Ed25519 signature, and a
// newline. Used by the signing tools; a panel never signs.
func SignSums(sums []byte, priv ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sumsPayload(sums))) + "\n")
}

// VerifySums checks sig — a SHA256SUMS.sig — over sums against keys and
// names the key that made it.
func VerifySums(sums, sig []byte, keys []Key) (Key, error) {
	s := strings.TrimSpace(string(sig))
	if s == "" {
		return Key{}, ErrSumsUnsigned
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return Key{}, ErrSumsBadSignature
	}
	for _, k := range keys {
		if ed25519.Verify(k.Public, sumsPayload(sums), raw) {
			return k, nil
		}
	}
	return Key{}, ErrSumsBadSignature
}

// ParseSums reads SHA256SUMS: one "<hex>  <name>" line per file (a "*"
// before the name, sha256sum's binary mode, is dropped), lower-cased hex.
// A name listed twice, or a line that is not a SHA-256, refuses the file.
func ParseSums(sums []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("SHA256SUMS line %d is not \"<sha256>  <file>\"", n)
		}
		sum, name := strings.ToLower(f[0]), strings.TrimPrefix(f[1], "*")
		if b, err := hex.DecodeString(sum); err != nil || len(b) != 32 {
			return nil, fmt.Errorf("SHA256SUMS line %d is not a SHA-256", n)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("SHA256SUMS lists %s twice", name)
		}
		out[name] = sum
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
