package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// TestASignedSHA256SUMS: the developer's key signs the checksums; another
// key, a changed line, an empty signature, or a manifest's signature over
// the same bytes do not pass. The checksums parse as sha256sum writes them.
func TestASignedSHA256SUMS(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	dev := Key{Name: "developer", Public: priv.Public().(ed25519.PublicKey)}
	sums := []byte(strings.Repeat("ab", 32) + "  shop-linux-amd64.tar.gz\n" + strings.Repeat("CD", 32) + " *install.sh\n")
	sig := SignSums(sums, priv)

	if k, err := VerifySums(sums, sig, []Key{NXKey(), dev}); err != nil || k.Name != "developer" {
		t.Fatalf("the developer's own signature: %v %v", k, err)
	}
	if _, err := VerifySums(sums, SignSums(sums, other), []Key{dev}); !errors.Is(err, ErrSumsBadSignature) {
		t.Fatalf("another key's signature: %v", err)
	}
	changed := []byte(strings.Replace(string(sums), "ab", "ac", 1))
	if _, err := VerifySums(changed, sig, []Key{dev}); !errors.Is(err, ErrSumsBadSignature) {
		t.Fatalf("a changed line: %v", err)
	}
	if _, err := VerifySums(sums, []byte(" \n"), []Key{dev}); !errors.Is(err, ErrSumsUnsigned) {
		t.Fatalf("an empty signature: %v", err)
	}
	// A signature over the bare bytes — what a manifest's signing would
	// make of them — is not a checksums signature.
	bare := []byte(base64Sig(ed25519.Sign(priv, sums)))
	if _, err := VerifySums(sums, bare, []Key{dev}); !errors.Is(err, ErrSumsBadSignature) {
		t.Fatalf("a signature without the domain: %v", err)
	}

	got, err := ParseSums(sums)
	if err != nil || got["shop-linux-amd64.tar.gz"] != strings.Repeat("ab", 32) || got[InstallScript] != strings.Repeat("cd", 32) {
		t.Fatalf("parsed %v %v", got, err)
	}
	for _, bad := range []string{
		"abc  file\n",
		strings.Repeat("ab", 32) + "\n",
		strings.Repeat("ab", 32) + "  a\n" + strings.Repeat("cd", 32) + "  a\n",
	} {
		if _, err := ParseSums([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func base64Sig(sig []byte) string { return base64.StdEncoding.EncodeToString(sig) }
