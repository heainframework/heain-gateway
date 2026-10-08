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

// testInside is the inside key open uses (the migration test reads with it).
var testInside = func() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }()

func open(t *testing.T) (*Store, *fakeKMS, string) {
	kms := &fakeKMS{keys: map[string][]byte{}}
	inside := testInside
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
	if err := s.CreateCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.Credential(ctx, "somchai")
	if err != nil || got.PasswordH != c.PasswordH || got.TOTPSecret != c.TOTPSecret {
		t.Fatalf("read: %+v %v", got, err)
	}
	if _, err := s.Credential(ctx, "nobody"); err != ErrNotFound {
		t.Fatal("missing")
	}
	_ = s.CreateSession(Session{Hash: "h1", User: "somchai", Kind: "web", ID: "sid-SECRET", Expires: time.Now().Add(time.Hour)})
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
	_ = s.CreateCredential(ctx, Credential{User: "a", PasswordH: "x"})
	n := len(kms.keys)
	if err := s.DeleteCredential(ctx, "a"); err != nil || len(kms.keys) != n-1 {
		t.Fatal("delete must destroy the key")
	}
	now := time.Now()
	for _, h := range []string{"s1", "s2"} {
		_ = s.CreateSession(Session{Hash: h, User: "u1", Kind: "web", Expires: now.Add(time.Hour)})
	}
	_ = s.CreateSession(Session{Hash: "s3", User: "u2", Expires: now.Add(-time.Second)})
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

func TestReplicationHooksAndMigrate(t *testing.T) {
	ctx := context.Background()
	// an instance before zone sync: node inside key, node credential keys
	node, nodeKMS, p := open(t)
	if err := node.CreateCredential(ctx, Credential{User: "alice", PasswordH: "h1", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_ = node.CreateSession(Session{Hash: "aaaa", User: "alice", Kind: "web", Expires: time.Now().Add(time.Hour)})
	node.Close()
	// reopen the same file under zone keys and migrate
	zoneKMS := &fakeKMS{keys: map[string][]byte{}}
	zone := make([]byte, 32)
	_, _ = rand.Read(zone)
	z, err := Open(p, zone, Keys{Sealer: zoneKMS.sealer, Destroy: zoneKMS.destroy})
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var writes []string
	z.OnWrite = func(st, k string, v []byte) {
		writes = append(writes, st+":"+map[bool]string{true: "del", false: "put"}[v == nil])
	}
	moved, dropped, err := z.Migrate(ctx, testInside, Keys{Sealer: nodeKMS.sealer, Destroy: nodeKMS.destroy})
	if err != nil || moved != 1 || dropped != 1 {
		t.Fatalf("migrate: %d %d %v", moved, dropped, err)
	}
	c, err := z.Credential(ctx, "alice")
	if err != nil || c.PasswordH != "h1" {
		t.Fatalf("credential after migration: %v %v", c, err)
	}
	if len(nodeKMS.keys) != 0 {
		t.Fatal("the old per-account node key must be destroyed")
	}
	if len(writes) == 0 {
		t.Fatal("migration writes must reach the change log")
	}
	// a record copied raw opens on another gateway with the same zone keys
	peerPath := filepath.Join(t.TempDir(), "peer.db")
	peer, _ := Open(peerPath, zone, Keys{Sealer: zoneKMS.sealer, Destroy: zoneKMS.destroy})
	defer peer.Close()
	all, _ := z.All("credential")
	for k, v := range all {
		if err := peer.Target("credential").ApplyRaw(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if c, err := peer.Credential(ctx, "alice"); err != nil || c.PasswordH != "h1" {
		t.Fatal("a raw copy must open on a peer with the same zone keys")
	}
	// a revocation is a delete the change log sees
	writes = nil
	_ = z.CreateSession(Session{Hash: "bbbb", User: "alice", Kind: "web", Expires: time.Now().Add(time.Hour)})
	if n, _ := z.RevokeUser("alice"); n != 1 {
		t.Fatal("revoke")
	}
	if writes[len(writes)-2] != "session:del" && writes[len(writes)-1] != "session:del" {
		t.Fatalf("revocation not logged: %v", writes)
	}
	if err := peer.Target("nope").ApplyRaw("k", nil); err == nil {
		t.Fatal("unknown store accepted")
	}
}

func TestUpdatesNeverResurrect(t *testing.T) {
	ctx := context.Background()
	s, _, _ := open(t)
	if err := s.PutCredential(ctx, Credential{User: "ghost", PasswordH: "x"}); err != ErrNotFound {
		t.Fatalf("an update of a missing credential must fail: %v", err)
	}
	_ = s.CreateCredential(ctx, Credential{User: "bob", PasswordH: "x"})
	c, _ := s.Credential(ctx, "bob")
	_ = s.DeleteCredential(ctx, "bob")
	c.Failures++
	if err := s.PutCredential(ctx, c); err != ErrNotFound {
		t.Fatal("a removed credential must not come back through an update")
	}
	ss := Session{Hash: "h9", User: "bob", Kind: "web", Expires: time.Now().Add(time.Hour)}
	_ = s.CreateSession(ss)
	_, _ = s.RevokeUser("bob")
	if err := s.PutSession(ss); err != ErrNotFound {
		t.Fatal("a revoked session must not come back through an update")
	}
	if err := s.Replace("h9", Session{Hash: "h10", User: "bob"}); err != ErrNotFound {
		t.Fatal("a revoked mobile session must not rotate")
	}
}
