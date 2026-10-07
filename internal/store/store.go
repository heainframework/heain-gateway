// Package store keeps heain-gateway's own state, all of it sealed under data
// keys held by heain-core's KMS:
//
//   - credentials of built-in accounts (password hash, TOTP secret, lockout
//     state), each account's under its own key cred-<index>, so removing an
//     account destroys that key (crypto-shred);
//   - sessions (web and mobile), under the app's inside key, found by the
//     sha256 of their token -- a token itself is never stored.
//
// Who an account is and its roles live in heain-database (author decision
// 2026-10-07); this store holds only what proves a login.
package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	bolt "go.etcd.io/bbolt"
)

var (
	bCreds    = []byte("credentials")
	bSessions = []byte("sessions")
	bUserSess = []byte("user_sessions") // <user index>/<session hash> -> ""
)

// ErrNotFound: no such record.
var ErrNotFound = errors.New("not found")

// Keys gives the per-account credential keys (core's KMS).
type Keys struct {
	Sealer  func(ctx context.Context, name string) (*heain.Sealer, error)
	Destroy func(ctx context.Context, name string) error
}

// Store is the gateway's sealed state.
type Store struct {
	db     *bolt.DB
	inside *heain.Sealer
	ixKey  []byte
	keys   Keys
}

// Open opens (creating) the store at path; inside is the app's inside key.
func Open(path string, inside []byte, keys Keys) (*Store, error) {
	s, err := heain.NewSealer(inside)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bCreds, bSessions, bUserSess} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	m := hmac.New(sha256.New, inside)
	m.Write([]byte("heain-gateway/index"))
	return &Store{db: db, inside: s, ixKey: m.Sum(nil), keys: keys}, nil
}

// Close closes the store.
func (s *Store) Close() error { return s.db.Close() }

// Index is the blinded index of an account id.
func (s *Store) Index(id string) string {
	m := hmac.New(sha256.New, s.ixKey)
	m.Write([]byte(id))
	return hex.EncodeToString(m.Sum(nil))
}

// Credential proves a built-in account's login.
type Credential struct {
	User        string    `json:"user"`
	PasswordH   string    `json:"pw"`
	MustChange  bool      `json:"must_change,omitempty"`
	TOTPSecret  string    `json:"totp,omitempty"`
	TOTPOn      bool      `json:"totp_on,omitempty"`
	TOTPLast    uint64    `json:"totp_last,omitempty"` // last counter accepted (no replay)
	Failures    int       `json:"failures,omitempty"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
	Created     time.Time `json:"created"`
	Changed     time.Time `json:"changed"`
}

type credEnvelope struct {
	Key    string `json:"key"`
	Sealed []byte `json:"sealed"`
}

func (s *Store) credKeyName(ix string) string { return "cred-" + ix[:24] }

// PutCredential stores c (sealed under the account's own key).
func (s *Store) PutCredential(ctx context.Context, c Credential) error {
	ix := s.Index(c.User)
	kn := s.credKeyName(ix)
	ks, err := s.keys.Sealer(ctx, kn)
	if err != nil {
		return fmt.Errorf("credential key: %w", err)
	}
	raw, _ := json.Marshal(c)
	env, _ := json.Marshal(credEnvelope{Key: kn, Sealed: ks.Seal(raw, []byte("cred/"+ix))})
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bCreds).Put([]byte(ix), s.inside.Seal(env, []byte("credenv/"+ix)))
	})
}

// Credential reads a built-in account's credential.
func (s *Store) Credential(ctx context.Context, user string) (Credential, error) {
	ix := s.Index(user)
	var sealed []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bCreds).Get([]byte(ix)); v != nil {
			sealed = append([]byte(nil), v...)
		}
		return nil
	})
	if sealed == nil {
		return Credential{}, ErrNotFound
	}
	envRaw, err := s.inside.Open(sealed, []byte("credenv/"+ix))
	if err != nil {
		return Credential{}, err
	}
	var env credEnvelope
	if err := json.Unmarshal(envRaw, &env); err != nil {
		return Credential{}, err
	}
	ks, err := s.keys.Sealer(ctx, env.Key)
	if err != nil {
		return Credential{}, fmt.Errorf("credential key: %w", err)
	}
	raw, err := ks.Open(env.Sealed, []byte("cred/"+ix))
	if err != nil {
		return Credential{}, err
	}
	var c Credential
	return c, json.Unmarshal(raw, &c)
}

// HasCredentials reports whether any built-in account exists.
func (s *Store) HasCredentials() bool {
	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error { n = tx.Bucket(bCreds).Stats().KeyN; return nil })
	return n > 0
}

// DeleteCredential removes an account's credential and destroys its key.
func (s *Store) DeleteCredential(ctx context.Context, user string) error {
	ix := s.Index(user)
	if err := s.keys.Destroy(ctx, s.credKeyName(ix)); err != nil {
		return fmt.Errorf("destroying the credential key: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bCreds).Delete([]byte(ix)) })
}

// Session is a signed-in person's session.
type Session struct {
	Hash       string    `json:"-"`
	User       string    `json:"user"`
	Name       string    `json:"name,omitempty"`
	Roles      []string  `json:"roles,omitempty"`
	AMR        string    `json:"amr"`
	Kind       string    `json:"kind"` // web | mobile
	CSRF       string    `json:"csrf,omitempty"`
	ID         string    `json:"id"` // public session id (assertion sid), not the token
	Created    time.Time `json:"created"`
	LastSeen   time.Time `json:"last_seen"`
	Expires    time.Time `json:"expires"`               // absolute end
	AccessExp  time.Time `json:"access_exp,omitempty"`  // mobile: this access token's end
	RefreshH   string    `json:"refresh_h,omitempty"`   // mobile: sha256 of the refresh token
	ClientAddr string    `json:"client_addr,omitempty"` // where it was created
}

func (s *Store) putSession(tx *bolt.Tx, ss Session) error {
	raw, _ := json.Marshal(ss)
	if err := tx.Bucket(bSessions).Put([]byte(ss.Hash), s.inside.Seal(raw, []byte("session/"+ss.Hash))); err != nil {
		return err
	}
	return tx.Bucket(bUserSess).Put([]byte(s.Index(ss.User)+"/"+ss.Hash), []byte{})
}

// PutSession stores ss under its token hash.
func (s *Store) PutSession(ss Session) error {
	return s.db.Update(func(tx *bolt.Tx) error { return s.putSession(tx, ss) })
}

// Session finds a session by token hash.
func (s *Store) Session(hash string) (Session, error) {
	var sealed []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bSessions).Get([]byte(hash)); v != nil {
			sealed = append([]byte(nil), v...)
		}
		return nil
	})
	if sealed == nil {
		return Session{}, ErrNotFound
	}
	raw, err := s.inside.Open(sealed, []byte("session/"+hash))
	if err != nil {
		return Session{}, err
	}
	var ss Session
	if err := json.Unmarshal(raw, &ss); err != nil {
		return Session{}, err
	}
	ss.Hash = hash
	return ss, nil
}

// Replace swaps session old for nw atomically (mobile refresh rotation).
func (s *Store) Replace(old string, nw Session) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		ss, err := s.Session(old)
		if err == nil {
			_ = tx.Bucket(bUserSess).Delete([]byte(s.Index(ss.User) + "/" + old))
		}
		if err := tx.Bucket(bSessions).Delete([]byte(old)); err != nil {
			return err
		}
		return s.putSession(tx, nw)
	})
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(hash string) error {
	ss, _ := s.Session(hash)
	return s.db.Update(func(tx *bolt.Tx) error {
		if ss.User != "" {
			_ = tx.Bucket(bUserSess).Delete([]byte(s.Index(ss.User) + "/" + hash))
		}
		return tx.Bucket(bSessions).Delete([]byte(hash))
	})
}

// RevokeUser removes every session of user; it returns how many.
func (s *Store) RevokeUser(user string) (int, error) {
	pfx := []byte(s.Index(user) + "/")
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bUserSess).Cursor()
		var keys [][]byte
		for k, _ := c.Seek(pfx); k != nil && len(k) >= len(pfx) && string(k[:len(pfx)]) == string(pfx); k, _ = c.Next() {
			keys = append(keys, append([]byte(nil), k...))
		}
		for _, k := range keys {
			h := k[len(pfx):]
			if tx.Bucket(bSessions).Get(h) != nil {
				n++
			}
			_ = tx.Bucket(bSessions).Delete(h)
			_ = tx.Bucket(bUserSess).Delete(k)
		}
		return nil
	})
	return n, err
}

// Sweep removes expired sessions; it returns how many.
func (s *Store) Sweep(now time.Time) int {
	var dead []string
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bSessions).ForEach(func(k, v []byte) error {
			raw, err := s.inside.Open(v, []byte("session/"+string(k)))
			var ss Session
			if err != nil || json.Unmarshal(raw, &ss) != nil || now.After(ss.Expires) {
				dead = append(dead, string(k))
			}
			return nil
		})
	})
	for _, h := range dead {
		_ = s.DeleteSession(h)
	}
	return len(dead)
}
