package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

type fakeKMS struct{ keys map[string][]byte }

func (f *fakeKMS) sealer(_ context.Context, name string) (*heain.Sealer, error) {
	k, ok := f.keys[name]
	if !ok {
		k = make([]byte, 32)
		_, _ = rand.Read(k)
		f.keys[name] = k
	}
	return heain.NewSealer(k)
}
func (f *fakeKMS) destroy(_ context.Context, name string) error { delete(f.keys, name); return nil }

func open(t *testing.T) (*Store, *fakeKMS, string) {
	kms := &fakeKMS{keys: map[string][]byte{}}
	inside := make([]byte, 32)
	_, _ = rand.Read(inside)
	p := filepath.Join(t.TempDir(), "gw.db")
	s, err := Open(p, inside, Keys{Sealer: kms.sealer, Destroy: kms.destroy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, kms, p
}

func TestCredentials(t *testing.T) {
	s, kms, p := open(t)
	ctx := context.Background()
	if s.HasCredentials() {
		t.Fatal("empty")
	}
	c := Credential{User: "somchai", PasswordH: "HASH-SECRET-xyz", TOTPSecret: "TOTPSECRETABCDEF", Created: time.Now()}
	if err := s.PutCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.Credential(ctx, "somchai")
	if err != nil || got.PasswordH != c.PasswordH || got.TOTPSecret != c.TOTPSecret {
		t.Fatalf("read: %+v %v", got, err)
	}
	if _, err := s.Credential(ctx, "nobody"); err != ErrNotFound {
		t.Fatal("missing")
	}
	_ = s.PutSession(Session{Hash: "h1", User: "somchai", Kind: "web", ID: "sid-SECRET", Expires: time.Now().Add(time.Hour)})
	s.Close()
	raw, _ := os.ReadFile(p)
	for _, secret := range []string{"somchai", "HASH-SECRET", "TOTPSECRET", "sid-SECRET"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("%q in plaintext on disk", secret)
		}
	}
	s2, err := Open(p, nil, Keys{})
	if err == nil {
		s2.Close()
		t.Fatal("a nil key must not open")
	}
	_ = kms
}

func TestCryptoShredAndSessions(t *testing.T) {
	s, kms, _ := open(t)
	ctx := context.Background()
	_ = s.PutCredential(ctx, Credential{User: "a", PasswordH: "x"})
	n := len(kms.keys)
	if err := s.DeleteCredential(ctx, "a"); err != nil || len(kms.keys) != n-1 {
		t.Fatal("delete must destroy the key")
	}
	now := time.Now()
	for _, h := range []string{"s1", "s2"} {
		_ = s.PutSession(Session{Hash: h, User: "u1", Kind: "web", Expires: now.Add(time.Hour)})
	}
	_ = s.PutSession(Session{Hash: "s3", User: "u2", Expires: now.Add(-time.Second)})
	if ss, err := s.Session("s1"); err != nil || ss.User != "u1" || ss.Hash != "s1" {
		t.Fatal("session")
	}
	if err := s.Replace("s2", Session{Hash: "s4", User: "u1", Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session("s2"); err != ErrNotFound {
		t.Fatal("replaced")
	}
	if n := s.Sweep(now); n != 1 {
		t.Fatalf("sweep %d", n)
	}
	if n, _ := s.RevokeUser("u1"); n != 2 {
		t.Fatalf("revoke %d", n)
	}
	if _, err := s.Session("s4"); err != ErrNotFound {
		t.Fatal("revoked")
	}
}
