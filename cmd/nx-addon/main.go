// Command nx-addon checks and signs an addon's manifest.
//
//	nx-addon check  nx-addon.json      # is it a manifest a panel accepts?
//	nx-addon keygen -out addon.key         # a developer key (keep it secret)
//	nx-addon sign   -key addon.key nx-addon.json > signed.json
//	nx-addon verify -pub <base64> nx-addon.json
//	nx-addon sign-sums   -key addon.key SHA256SUMS > SHA256SUMS.sig
//	nx-addon verify-sums -pub <base64> SHA256SUMS SHA256SUMS.sig
//
// A verified addon is signed with its developer's own key, which the
// directory at addons.nx-panel.org vouches for; an official one with
// NX's. The signature covers every field, so any edit means signing
// again — and the version changes with every release.
//
// A release's SHA256SUMS is signed with the same key, after the build, and
// SHA256SUMS.sig uploaded beside it: the panel runs a release's install.sh,
// or installs its binary, only when both match checksums the manifest's key
// signed.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nx-panel/addon-kit/manifest"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "check":
		raw := readArg(args)
		m, err := manifest.Parse(raw)
		if err != nil {
			fail("manifest", err)
		}
		fmt.Printf("ok: %s %s (api %d)\n", m.Slug, m.Version, m.API)
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		out := fs.String("out", "addon.key", "where to write the private key")
		_ = fs.Parse(args)
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fail("keygen", err)
		}
		// Never over an existing key: the directory vouches for it, and a
		// release signed by a new one is no longer the developer's.
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			fail("write key", err)
		}
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			fail("write key", err)
		}
		fmt.Printf("private key: %s (keep it out of the repository)\npublic key:  %s\n", *out, base64.StdEncoding.EncodeToString(pub))
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		keyPath := fs.String("key", "addon.key", "the private key")
		dev := fs.Bool("dev", false, "sign with the development key, which only a panel built with -tags addondev trusts")
		_ = fs.Parse(args)
		raw := readArg(fs.Args())
		if _, err := manifest.Parse(raw); err != nil {
			fail("manifest", err)
		}
		priv := manifest.DevPrivateKey()
		if !*dev {
			var err error
			if priv, err = loadKey(*keyPath); err != nil {
				fail("load key", err)
			}
		}
		signed, err := manifest.Sign(raw, priv)
		if err != nil {
			fail("sign", err)
		}
		fmt.Println(string(signed))
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		pub := fs.String("pub", "", "a developer's public key (base64); NX's and the development key are always tried")
		_ = fs.Parse(args)
		raw := readArg(fs.Args())
		k, err := manifest.Verify(raw, keysWith(*pub))
		if err != nil {
			fail("verify", err)
		}
		fmt.Printf("signed by: %s\n", k.Name)
	case "sign-sums":
		fs := flag.NewFlagSet("sign-sums", flag.ExitOnError)
		keyPath := fs.String("key", "addon.key", "the private key — the one that signs the manifest")
		dev := fs.Bool("dev", false, "sign with the development key, which only a panel built with -tags addondev trusts")
		_ = fs.Parse(args)
		sums := readArg(fs.Args())
		if _, err := manifest.ParseSums(sums); err != nil {
			fail("SHA256SUMS", err)
		}
		priv := manifest.DevPrivateKey()
		if !*dev {
			var err error
			if priv, err = loadKey(*keyPath); err != nil {
				fail("load key", err)
			}
		}
		_, _ = os.Stdout.Write(manifest.SignSums(sums, priv))
	case "verify-sums":
		fs := flag.NewFlagSet("verify-sums", flag.ExitOnError)
		pub := fs.String("pub", "", "a developer's public key (base64); NX's and the development key are always tried")
		_ = fs.Parse(args)
		if fs.NArg() != 2 {
			usage()
		}
		sums, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			fail("read", err)
		}
		sig, err := os.ReadFile(fs.Arg(1))
		if err != nil {
			fail("read", err)
		}
		k, err := manifest.VerifySums(sums, sig, keysWith(*pub))
		if err != nil {
			fail("verify", err)
		}
		fmt.Printf("signed by: %s\n", k.Name)
	default:
		usage()
	}
}

// keysWith is NX's key, the development key and, when given, a
// developer's base64 public key.
func keysWith(pub string) []manifest.Key {
	keys := []manifest.Key{manifest.NXKey(), manifest.DevKey()}
	if pub != "" {
		b, err := base64.StdEncoding.DecodeString(pub)
		if err != nil || len(b) != ed25519.PublicKeySize {
			fail("pub", fmt.Errorf("not a base64 Ed25519 public key"))
		}
		keys = append(keys, manifest.Key{Name: "developer", Public: ed25519.PublicKey(b)})
	}
	return keys
}

func readArg(args []string) []byte {
	if len(args) != 1 {
		usage()
	}
	var raw []byte
	var err error
	if args[0] == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(args[0])
	}
	if err != nil {
		fail("read", err)
	}
	return raw
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s is not a base64 Ed25519 private key", path)
	}
	return ed25519.PrivateKey(b), nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nx-addon check|keygen|sign|verify|sign-sums|verify-sums …")
	os.Exit(2)
}

func fail(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}
