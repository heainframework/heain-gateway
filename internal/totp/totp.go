// Package totp is RFC 6238 time-based one-time passwords (HMAC-SHA1, 6
// digits, 30-second steps -- what authenticator apps use).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Step is the time step.
const Step = 30 * time.Second

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret is a random 160-bit secret, base32 (no padding).
func NewSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

// Code is the code for counter c.
func Code(secret string, c uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("totp: bad secret: %w", err)
	}
	m := hmac.New(sha1.New, key)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], c)
	m.Write(buf[:])
	s := m.Sum(nil)
	o := s[len(s)-1] & 0x0f
	v := binary.BigEndian.Uint32(s[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// Counter is the step counter at t.
func Counter(t time.Time) uint64 { return uint64(t.Unix()) / uint64(Step/time.Second) }

// Verify checks code at t, allowing one step of clock drift either way.
// It returns the matching counter, so a caller can refuse a code used
// before (counter <= the last one accepted).
func Verify(secret, code string, t time.Time) (uint64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	c := Counter(t)
	for _, d := range []int64{0, -1, 1} {
		n := uint64(int64(c) + d)
		want, err := Code(secret, n)
		if err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return n, true
		}
	}
	return 0, false
}

// URI is the otpauth:// URI an authenticator app scans.
func URI(issuer, account, secret string) string {
	v := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}
