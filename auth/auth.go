// Package auth is what an addon's own admin sign-in is made of: bcrypt
// passwords, session tokens kept only as hashes, a TOTP second factor that
// authenticator apps treat as the panel's, and a limiter for failed
// attempts. Where accounts and sessions are stored is the addon's: this
// package holds no state but the limiter's.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nx-panel/addon-kit/manifest"
	"golang.org/x/crypto/bcrypt"
)

// MinPassword is the shortest password HashPassword takes; a manifest's
// password option holds the install's answer to the same rule.
const MinPassword = manifest.MinPassword

// MaxPasswordBytes is the most bcrypt reads of a password: 72 bytes, which
// is 72 Latin letters but 36 Persian or Russian ones and 24 Chinese.
const MaxPasswordBytes = manifest.MaxPasswordBytes

// ErrShortPassword is a password under MinPassword characters;
// ErrLongPassword one over MaxPasswordBytes bytes.
var (
	ErrShortPassword = errors.New("a password is at least 10 characters")
	ErrLongPassword  = errors.New("a password is at most 72 bytes (about 36 Persian or Russian letters, 24 Chinese)")
)

// HashPassword is bcrypt at its default cost.
func HashPassword(p string) (string, error) {
	if utf8.RuneCountInString(p) < MinPassword {
		return "", ErrShortPassword
	}
	if len(p) > MaxPasswordBytes {
		return "", ErrLongPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword compares a password with a hash.
func CheckPassword(hash, p string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil
}

// RandomToken is 32 random bytes, hex: a session or a one-time link.
func RandomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// HashToken is what a store keeps of a token, so a copy of the database
// signs nobody in.
func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// ClientAddr is the request's peer address without the port. It is the
// connection's, never a forwarded header's: an addon behind a proxy it
// trusts sets r.RemoteAddr itself.
func ClientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Limiter counts failures per key (a client address, say) in a sliding
// window. The zero value is not usable; make one with NewLimiter. An IPv6
// address counts as its /64, which one client holds whole.
type Limiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu       sync.Mutex
	seen     map[string][]time.Time
	inflight map[string]int
	// sweepNext is the size at which fail sweeps out aged keys next: twice
	// what a sweep leaves, so the cost is spread over the failures.
	sweepNext int
}

// NewLimiter locks a key out after max failures within window.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, now: time.Now, seen: map[string][]time.Time{}, inflight: map[string]int{}, sweepNext: sweepAt}
}

// sweepAt is how many keys the limiter holds before it drops every key
// whose failures have all aged out.
const sweepAt = 1024

// limitKey is the key an address is counted under: an IPv6 address's /64.
func limitKey(key string) string {
	if a, err := netip.ParseAddr(key); err == nil && a.Is6() && !a.Is4In6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return key
}

// recent drops key's failures older than the window and answers how many
// are left. l.mu is held.
func (l *Limiter) recent(key string, cut time.Time) int {
	kept := l.seen[key][:0]
	for _, at := range l.seen[key] {
		if at.After(cut) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.seen, key)
	} else {
		l.seen[key] = kept
	}
	return len(kept)
}

// Locked reports whether key has failed max times within the window,
// forgetting older failures as it goes.
func (l *Limiter) Locked(key string) bool {
	key = limitKey(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.recent(key, l.now().Add(-l.window)) >= l.max
}

// Try is Locked and Fail made one: it reserves an attempt for key, counting
// the attempts still being checked as failures, so N guesses sent at once
// get no more than max checked. ok false is locked out. Call done once with
// whether the attempt failed.
func (l *Limiter) Try(key string) (done func(failed bool), ok bool) {
	key = limitKey(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.recent(key, l.now().Add(-l.window))+l.inflight[key] >= l.max {
		return func(bool) {}, false
	}
	l.inflight[key]++
	var once sync.Once
	return func(failed bool) {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.inflight[key]--; l.inflight[key] <= 0 {
				delete(l.inflight, key)
			}
			if failed {
				l.fail(key)
			}
		})
	}, true
}

// Fail records one failure for key.
func (l *Limiter) Fail(key string) {
	key = limitKey(key)
	l.mu.Lock()
	l.fail(key)
	l.mu.Unlock()
}

// fail records a failure and, once the keys have doubled since the last
// sweep, forgets every key whose failures have all aged out. l.mu is held.
func (l *Limiter) fail(key string) {
	l.seen[key] = append(l.seen[key], l.now())
	if len(l.seen) > l.sweepNext {
		cut := l.now().Add(-l.window)
		for k := range l.seen {
			l.recent(k, cut)
		}
		l.sweepNext = max(sweepAt, 2*len(l.seen))
	}
}
