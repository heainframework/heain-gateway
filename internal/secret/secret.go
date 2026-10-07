// Package secret hashes passwords (PBKDF2-HMAC-SHA256, Go standard library)
// and makes random tokens.
package secret

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Iterations of PBKDF2-HMAC-SHA256 for new hashes (OWASP 2023: 600 000).
var Iterations = 600000

var b64 = base64.RawStdEncoding

// MinPasswordLen is the shortest password accepted.
const MinPasswordLen = 10

// CheckPolicy refuses weak passwords.
func CheckPolicy(pw, user string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLen {
		return fmt.Errorf("a password needs at least %d characters", MinPasswordLen)
	}
	if utf8.RuneCountInString(pw) > 256 {
		return errors.New("a password is at most 256 characters")
	}
	if user != "" && strings.Contains(strings.ToLower(pw), strings.ToLower(user)) {
		return errors.New("a password must not contain the user name")
	}
	return nil
}

// Hash is "pbkdf2-sha256$<iter>$<salt>$<hash>".
func Hash(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", Iterations, b64.EncodeToString(salt), b64.EncodeToString(dk)), nil
}

// Verify checks pw against a Hash value (constant time).
func Verify(pw, h string) bool {
	p := strings.Split(h, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	it, err := strconv.Atoi(p[1])
	if err != nil || it < 1000 {
		return false
	}
	salt, err1 := b64.DecodeString(p[2])
	want, err2 := b64.DecodeString(p[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, it, len(want))
	return err == nil && subtle.ConstantTimeCompare(dk, want) == 1
}

// Token is a random URL-safe token of n bytes.
func Token(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// SHA256 is the hex sha256 of s (for storing tokens by hash).
func SHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}
