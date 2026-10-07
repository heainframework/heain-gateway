package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA1, secret "12345678901234567890", last 6 digits
	sec := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"} {
		got, err := Code(sec, Counter(time.Unix(ts, 0)))
		if err != nil || got != want {
			t.Errorf("t=%d: %s %v, want %s", ts, got, err, want)
		}
	}
	now := time.Unix(1111111111, 0)
	c, _ := Code(sec, Counter(now)-1)
	if _, ok := Verify(sec, c, now); !ok {
		t.Fatal("one step of drift must pass")
	}
	c, _ = Code(sec, Counter(now)-2)
	if _, ok := Verify(sec, c, now); ok {
		t.Fatal("two steps must not")
	}
	if _, ok := Verify(sec, "12345", now); ok {
		t.Fatal("short code")
	}
	if len(NewSecret()) != 32 {
		t.Fatal("secret length")
	}
}
