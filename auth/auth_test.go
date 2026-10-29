package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPasswordsAndTokens(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrShortPassword {
		t.Fatalf("short password: %v", err)
	}
	h, err := HashPassword("long enough password")
	if err != nil || !CheckPassword(h, "long enough password") || CheckPassword(h, "another password") {
		t.Fatalf("hash: %v", err)
	}
	a, b := RandomToken(), RandomToken()
	if len(a) != 64 || a == b || HashToken(a) == a || HashToken(a) != HashToken(a) {
		t.Fatal("tokens")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:5555"
	if ClientAddr(r) != "2001:db8::1" {
		t.Fatalf("addr %q", ClientAddr(r))
	}
}

// TestACodeIsTakenOnce: a code is good one step either side, never twice,
// and the enrolment URI names the addon.
func TestACodeIsTakenOnce(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	code := TOTPCode(secret, now)
	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("the current code was refused")
	}
	if _, ok := VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("the same code was taken twice")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, now.Add(-30*time.Second)), now, 0); !ok {
		t.Fatal("one step of skew was refused")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, now.Add(-90*time.Second)), now, 0); ok {
		t.Fatal("three steps back was taken")
	}
	uri := TOTPURI("NX Notif", "admin", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/NX%20Notif:admin?") || !strings.Contains(uri, "issuer=NX+Notif") {
		t.Fatalf("uri %s", uri)
	}
}

func TestTheLimiterForgets(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	at := time.Unix(1000, 0)
	l.now = func() time.Time { return at }
	for range 3 {
		if l.Locked("a") {
			t.Fatal("locked early")
		}
		l.Fail("a")
	}
	if !l.Locked("a") || l.Locked("b") {
		t.Fatal("three failures did not lock, or locked another key")
	}
	at = at.Add(61 * time.Second)
	if l.Locked("a") {
		t.Fatal("the window did not slide")
	}
}

// TestGuessesSentAtOnceAreCountedAtOnce: Try reserves an attempt, so a burst
// of guesses gets no more than max checked; an IPv6 /64 counts as one.
func TestGuessesSentAtOnceAreCountedAtOnce(t *testing.T) {
	l := NewLimiter(5, 10*time.Minute)
	var dones []func(bool)
	allowed := 0
	for range 50 {
		done, ok := l.Try("203.0.113.9")
		if ok {
			allowed++
			dones = append(dones, done)
		}
	}
	if allowed != 5 {
		t.Fatalf("%d guesses let through at once, want 5", allowed)
	}
	for _, d := range dones {
		d(true)
	}
	if !l.Locked("203.0.113.9") {
		t.Fatal("five failures did not lock")
	}
	for i := range 5 {
		l.Fail("2001:db8:1:2::" + string(rune('a'+i)))
	}
	if !l.Locked("2001:db8:1:2:ffff::1") {
		t.Fatal("another address in the same /64 was not locked")
	}
	if _, ok := l.Try("2001:db8:1:3::1"); !ok {
		t.Fatal("another /64 was locked")
	}
}

func TestAPasswordIsCountedInLetters(t *testing.T) {
	if _, err := HashPassword("رمزعبور"); err != ErrShortPassword { // 7 letters, 14 bytes
		t.Fatalf("seven Persian letters = %v", err)
	}
	if _, err := HashPassword("رمزعبورقوی!"); err != nil {
		t.Fatalf("ten Persian letters = %v", err)
	}
	if _, err := HashPassword(strings.Repeat("ж", 40)); err != ErrLongPassword {
		t.Fatalf("80 bytes = %v", err)
	}
}
