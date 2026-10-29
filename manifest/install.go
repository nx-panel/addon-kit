package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/semver"
)

// What api 1 adds to a manifest: the file sits at
// the root of the addon's repository, where the directory and the panel's
// install wizard read it before anything runs, and it says how the addon is
// installed and which questions the install asks. The running addon serves
// the same file at WellKnownPath, so registration reads what the install read.

// Requires is what an addon needs of the panel it is registered with.
type Requires struct {
	// Panel is the lowest panel release the addon works with, as ">=X.Y.Z" —
	// the one form a constraint takes here, since an addon's contract only
	// ever grows.
	Panel string `json:"panel,omitempty"`
}

// Install is how the addon is installed. An addon may ship either way or
// both; the operator (or the panel, installing on their behalf) picks.
type Install struct {
	// Docker is the image and the compose file, a path in the addon's
	// repository and release.
	Docker *DockerInstall `json:"docker,omitempty"`
	// Binary maps a platform ("linux-amd64") to the release asset holding the
	// program, installed under systemd by the addon's install script.
	Binary map[string]string `json:"binary,omitempty"`
	// Options are the questions the install asks. Their answers reach the
	// addon as environment variables (EnvName).
	Options []Option `json:"options,omitempty"`
}

// DockerInstall is an addon's container image and compose file.
type DockerInstall struct {
	Image   string `json:"image"`
	Compose string `json:"compose,omitempty"`
}

// Option is one question the install asks.
type Option struct {
	Key  string `json:"key"`
	Type string `json:"type"`
	// Label and Help are by language ("en", "fa", "ru", "zh"); English is
	// required, the others fall back to it.
	Label map[string]string `json:"label"`
	Help  map[string]string `json:"help,omitempty"`
	// Default is the answer before the operator changes it, a JSON value of
	// the option's type. A secret has none.
	Default  json.RawMessage `json:"default,omitempty"`
	Required bool            `json:"required,omitempty"`
	// Choices are a choice option's values.
	Choices []string `json:"choices,omitempty"`
	// When shows the option only while another option has a value: one pair,
	// naming an option declared before this one.
	When map[string]string `json:"when,omitempty"`
}

// The option types, a closed list: a manifest is a declaration, not a form
// language.
const (
	OptionString = "string"
	OptionSecret = "secret"
	OptionNumber = "number"
	OptionPort   = "port"
	OptionBool   = "bool"
	OptionChoice = "choice"
	OptionURL    = "url"
	// OptionPath is a base path the addon serves its admin under: one
	// segment, or "" for the root (NormalizeBasePath). The panel's install
	// wizard proposes a random one when the option has no default, and
	// joins the answer into the address it registers the addon at, as it
	// does the port. At most one per manifest.
	OptionPath = "path"
	// OptionPassword is a secret that becomes the addon's admin password: at
	// least MinPassword characters, the rule auth.HashPassword holds a
	// password to, so the panel refuses a shorter one before the install
	// runs instead of the addon refusing it after.
	OptionPassword = "password"
)

// MinPassword and MaxPasswordBytes are the bounds an addon's sign-in holds
// a password to (auth.MinPassword, auth.MaxPasswordBytes: bcrypt reads 72
// bytes), and so a password option's answer.
const (
	MinPassword      = 10
	MaxPasswordBytes = 72
)

// secretType is whether an option's answer is kept from sight: never
// shown, logged or given a default.
func secretType(t string) bool { return t == OptionSecret || t == OptionPassword }

// SecretType is secretType for the panel: whether an answer of this type is
// masked in its form and kept out of logs and the command it shows.
func SecretType(t string) bool { return secretType(t) }

var optionTypes = []string{OptionString, OptionSecret, OptionPassword, OptionNumber, OptionPort, OptionBool, OptionChoice, OptionURL, OptionPath}

// basePathPattern is one base-path segment, the rule the panel holds its own
// base path to: mounted verbatim as a URL prefix, so nothing that would need
// escaping.
var basePathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// NormalizeBasePath reads a base path as an operator may type it — "admin",
// "/admin", "/admin/", or "" and "/" for the root — and answers "/admin", or
// "" for the root.
func NormalizeBasePath(s string) (string, error) {
	s = strings.Trim(strings.TrimSpace(s), "/")
	if s == "" {
		return "", nil
	}
	if !basePathPattern.MatchString(s) {
		return "", errors.New("must be one path segment of letters, digits, - and _ (at most 64), or empty for the root")
	}
	return "/" + s, nil
}

// Languages are the ones a label may be written in: the panel's four.
var Languages = []string{"en", "fa", "ru", "zh"}

var (
	optionKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	platformPattern  = regexp.MustCompile(`^linux-(amd64|arm64|armv7|armv6|armv5|386|s390x|riscv64)$`)
	assetPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	panelReqPattern  = regexp.MustCompile(`^>=\s*v?(\d+\.\d+\.\d+)$`)
)

// EnvName is the environment variable an option's answer reaches the addon
// in: NX_OPT_ and the key in upper case.
func EnvName(key string) string { return "NX_OPT_" + strings.ToUpper(key) }

// The variables the install sets besides the options; the NX_OPT_ prefix
// keeps an option from ever spelling one of them.
const (
	EnvPanelURL  = "NX_PANEL_URL"
	EnvClaimCode = "NX_CLAIM_CODE"
)

// MaxRateLimit is the most requests a minute a manifest may ask for its
// token. The panel's default is 120.
const MaxRateLimit = 600

func checkV1(m Manifest) error {
	if err := checkLabels("description", m.Description, 500, false); err != nil {
		return err
	}
	if len(m.License) > 64 {
		return errors.New("license is too long (at most 64 characters)")
	}
	if m.Docs != "" && !absoluteHTTP(m.Docs) {
		return errors.New("docs must be an absolute http(s) URL")
	}
	if m.Requires != nil && m.Requires.Panel != "" && !panelReqPattern.MatchString(m.Requires.Panel) {
		return errors.New(`requires.panel must read ">=X.Y.Z"`)
	}
	if m.RateLimit < 0 || m.RateLimit > MaxRateLimit {
		return fmt.Errorf("rateLimit is requests a minute, from 1 to %d (0 for the panel's default)", MaxRateLimit)
	}
	if m.Install == nil {
		return nil
	}
	in := m.Install
	if in.Docker == nil && len(in.Binary) == 0 {
		return errors.New("install names neither a docker image nor a binary")
	}
	if in.Docker != nil {
		if !validImage(in.Docker.Image) {
			return errors.New("install.docker.image must be an image name without a tag (the release's version is the tag)")
		}
		if in.Docker.Compose != "" && !validRepoPath(in.Docker.Compose) {
			return errors.New("install.docker.compose must be a relative path in the addon's repository")
		}
	}
	for platform, asset := range in.Binary {
		if !platformPattern.MatchString(platform) {
			return fmt.Errorf("install.binary: %q is not a platform this panel installs on (linux-amd64, linux-arm64, …)", platform)
		}
		if !assetPattern.MatchString(asset) {
			return fmt.Errorf("install.binary.%s must be a release asset's file name", platform)
		}
	}
	return checkOptions(in.Options)
}

func checkOptions(opts []Option) error {
	if len(opts) > 32 {
		return errors.New("install.options: at most 32 options")
	}
	declared := map[string]Option{}
	paths := 0
	for i, o := range opts {
		where := fmt.Sprintf("install.options[%d]", i)
		if !optionKeyPattern.MatchString(o.Key) {
			return fmt.Errorf("%s: key must be lowercase letters, digits and _, starting with a letter (at most 32)", where)
		}
		where = "install.options." + o.Key
		if _, dup := declared[o.Key]; dup {
			return fmt.Errorf("%s is declared twice", where)
		}
		if !slices.Contains(optionTypes, o.Type) {
			return fmt.Errorf("%s: type must be one of %s", where, strings.Join(optionTypes, ", "))
		}
		if o.Type == OptionPath {
			if paths++; paths > 1 {
				return fmt.Errorf("%s: a manifest has at most one path option", where)
			}
		}
		if err := checkLabels(where+".label", o.Label, 80, true); err != nil {
			return err
		}
		if err := checkLabels(where+".help", o.Help, 300, false); err != nil {
			return err
		}
		if o.Type == OptionChoice {
			if len(o.Choices) == 0 || len(o.Choices) > 32 {
				return fmt.Errorf("%s: a choice needs between 1 and 32 choices", where)
			}
			seen := map[string]bool{}
			for _, c := range o.Choices {
				if c == "" || len(c) > 64 || seen[c] {
					return fmt.Errorf("%s: choice %q is empty, too long or repeated", where, c)
				}
				seen[c] = true
			}
		} else if len(o.Choices) > 0 {
			return fmt.Errorf("%s: only a choice has choices", where)
		}
		if len(o.Default) > 0 {
			if secretType(o.Type) {
				return fmt.Errorf("%s: a %s has no default", where, o.Type)
			}
			if err := checkValue(o, o.Default); err != nil {
				return fmt.Errorf("%s.default: %w", where, err)
			}
		}
		if len(o.When) > 0 {
			if len(o.When) != 1 {
				return fmt.Errorf("%s.when names one option", where)
			}
			for key, want := range o.When {
				ref, ok := declared[key]
				if !ok {
					return fmt.Errorf("%s.when names %q, which is not an option declared before it", where, key)
				}
				switch ref.Type {
				case OptionChoice:
					if !slices.Contains(ref.Choices, want) {
						return fmt.Errorf("%s.when: %q is not one of %s's choices", where, want, key)
					}
				case OptionBool:
					if want != "true" && want != "false" {
						return fmt.Errorf(`%s.when: %s is a bool, so the value is "true" or "false"`, where, key)
					}
				default:
					return fmt.Errorf("%s.when must name a choice or a bool option", where)
				}
			}
		}
		declared[o.Key] = o
	}
	return nil
}

// checkValue is whether a JSON value is an answer of the option's type.
// The install wizard calls it for what the operator typed, too.
func checkValue(o Option, raw json.RawMessage) error {
	switch o.Type {
	case OptionBool:
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			return errors.New("must be true or false")
		}
	case OptionNumber:
		var n float64
		if json.Unmarshal(raw, &n) != nil {
			return errors.New("must be a number")
		}
	case OptionPort:
		var n int
		if json.Unmarshal(raw, &n) != nil || n < 1 || n > 65535 {
			return errors.New("must be a port from 1 to 65535")
		}
	default:
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return errors.New("must be a string")
		}
		if len(s) > 1024 {
			return errors.New("is longer than 1024 characters")
		}
		switch o.Type {
		case OptionChoice:
			if !slices.Contains(o.Choices, s) {
				return fmt.Errorf("must be one of %s", strings.Join(o.Choices, ", "))
			}
		case OptionURL:
			if s != "" && !absoluteHTTP(s) {
				return errors.New("must be an absolute http(s) URL")
			}
		case OptionPath:
			if _, err := NormalizeBasePath(s); err != nil {
				return err
			}
		case OptionPassword:
			// Empty is no answer, which an optional password may be.
			switch {
			case s == "":
			case utf8.RuneCountInString(s) < MinPassword:
				return fmt.Errorf("must be at least %d characters", MinPassword)
			case len(s) > MaxPasswordBytes:
				return fmt.Errorf("must be at most %d bytes (about 36 Persian or Russian letters, 24 Chinese)", MaxPasswordBytes)
			}
		}
	}
	return nil
}

// CheckAnswer is checkValue for the install wizard: an operator's answer to
// one option.
func CheckAnswer(o Option, raw json.RawMessage) error { return checkValue(o, raw) }

func checkLabels(where string, labels map[string]string, max int, required bool) error {
	if required && strings.TrimSpace(labels["en"]) == "" {
		return fmt.Errorf("%s needs an English (en) text", where)
	}
	if len(labels) > 0 && strings.TrimSpace(labels["en"]) == "" {
		return fmt.Errorf("%s: English (en) is required whenever another language is given", where)
	}
	for lang, text := range labels {
		if !slices.Contains(Languages, lang) {
			return fmt.Errorf("%s: %q is not one of %s", where, lang, strings.Join(Languages, ", "))
		}
		if len(text) > max {
			return fmt.Errorf("%s.%s is longer than %d characters", where, lang, max)
		}
	}
	return nil
}

// validImage is a registry path without a tag or digest: the release's
// version is the tag, so a manifest cannot pin an image the release is not.
func validImage(s string) bool {
	if s == "" || len(s) > 255 || strings.ContainsAny(s, "@ \t") {
		return false
	}
	last := s[strings.LastIndex(s, "/")+1:]
	return !strings.Contains(last, ":") && s == strings.ToLower(s)
}

// validRepoPath is a relative path inside a repository.
func validRepoPath(p string) bool {
	if p == "" || len(p) > 256 || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\?# \t") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// SatisfiesPanel reports whether a panel release meets the manifest's
// requires.panel. A build without a release version (a development build)
// meets everything; so does a manifest that requires nothing.
func (m Manifest) SatisfiesPanel(version string) bool {
	if m.Requires == nil || m.Requires.Panel == "" {
		return true
	}
	have := "v" + strings.TrimPrefix(strings.TrimSpace(version), "v")
	if !semver.IsValid(have) {
		return true
	}
	need := "v" + panelReqPattern.FindStringSubmatch(m.Requires.Panel)[1]
	return semver.Compare(have, need) >= 0
}
