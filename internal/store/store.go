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
//
// Stage B-1c (author decisions 2026-10-08): with zone sync, the inside key
// and the per-account keys are zone keys, so every gateway of the zone
// holds the same sealed records; every write is told to OnWrite (the change
// log) and records from other gateways come in through ApplyRaw, as they
// are, never opened.
package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	// OnWrite, when set, is told every write after it is stored: the store
	// (credential, session, user_session), the key and the sealed value
	// (nil = deleted).
	OnWrite func(store, key string, sealed []byte)
}

// Replicated stores and their buckets.
var replicated = map[string][]byte{"credential": bCreds, "session": bSessions, "user_session": bUserSess}

type write struct {
	store, key string
	val        []byte
}

// put and del write in tx and remember the write for OnWrite.
func put(tx *bolt.Tx, store, key string, val []byte, ws *[]write) error {
	*ws = append(*ws, write{store, key, val})
	return tx.Bucket(replicated[store]).Put([]byte(key), val)
}

func del(tx *bolt.Tx, store, key string, ws *[]write) error {
	*ws = append(*ws, write{store, key, nil})
	return tx.Bucket(replicated[store]).Delete([]byte(key))
}

// update runs f in a write transaction and tells OnWrite what it wrote.
func (s *Store) update(f func(tx *bolt.Tx, ws *[]write) error) error {
	var ws []write
	if err := s.db.Update(func(tx *bolt.Tx) error { ws = ws[:0]; return f(tx, &ws) }); err != nil {
		return err
	}
	if s.OnWrite != nil {
		for _, w := range ws {
			s.OnWrite(w.store, w.key, w.val)
		}
	}
	return nil
}

// Target is one replicated store, for the change log.
type Target struct {
	s     *Store
	store string
}

// Target returns the replicated store name.
func (s *Store) Target(store string) Target { return Target{s: s, store: store} }

// ApplyRaw stores a sealed value from another gateway as it is (nil = delete).
func (t Target) ApplyRaw(key string, sealed []byte) error {
	b := replicated[t.store]
	if b == nil {
		return fmt.Errorf("store: unknown replicated store %q", t.store)
	}
	return t.s.db.Update(func(tx *bolt.Tx) error {
		if sealed == nil {
			return tx.Bucket(b).Delete([]byte(key))
		}
		return tx.Bucket(b).Put([]byte(key), sealed)
	})
}

// All returns every record of a replicated store (to log them once when
// zone sync starts).
func (s *Store) All(store string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(replicated[store]).ForEach(func(k, v []byte) error {
			out[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	return out, err
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

// CreateCredential stores c, making or replacing it (sealed under the
// account's own key).
func (s *Store) CreateCredential(ctx context.Context, c Credential) error {
	return s.putCredential(ctx, c, true)
}

// PutCredential updates an existing credential; ErrNotFound when it was
// removed meanwhile (also by another gateway of the zone), so an update
// never brings a removed account back.
func (s *Store) PutCredential(ctx context.Context, c Credential) error {
	return s.putCredential(ctx, c, false)
}

func (s *Store) putCredential(ctx context.Context, c Credential, create bool) error {
	ix := s.Index(c.User)
	kn := s.credKeyName(ix)
	ks, err := s.keys.Sealer(ctx, kn)
	if err != nil {
		return fmt.Errorf("credential key: %w", err)
	}
	raw, _ := json.Marshal(c)
	env, _ := json.Marshal(credEnvelope{Key: kn, Sealed: ks.Seal(raw, []byte("cred/"+ix))})
	return s.update(func(tx *bolt.Tx, ws *[]write) error {
		if !create && tx.Bucket(bCreds).Get([]byte(ix)) == nil {
			return ErrNotFound
		}
		return put(tx, "credential", ix, s.inside.Seal(env, []byte("credenv/"+ix)), ws)
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
	return s.update(func(tx *bolt.Tx, ws *[]write) error { return del(tx, "credential", ix, ws) })
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

func (s *Store) putSession(tx *bolt.Tx, ss Session, ws *[]write) error {
	raw, _ := json.Marshal(ss)
	if err := put(tx, "session", ss.Hash, s.inside.Seal(raw, []byte("session/"+ss.Hash)), ws); err != nil {
		return err
	}
	// the value is a marker, never empty: an empty value would travel as a delete
	return put(tx, "user_session", s.Index(ss.User)+"/"+ss.Hash, []byte{1}, ws)
}

// CreateSession stores a new session under its token hash.
func (s *Store) CreateSession(ss Session) error {
	return s.update(func(tx *bolt.Tx, ws *[]write) error { return s.putSession(tx, ss, ws) })
}

// PutSession updates an existing session; ErrNotFound when it was ended
// meanwhile (also on another gateway of the zone), so an update never
// brings a revoked session back.
func (s *Store) PutSession(ss Session) error {
	return s.update(func(tx *bolt.Tx, ws *[]write) error {
		if tx.Bucket(bSessions).Get([]byte(ss.Hash)) == nil {
			return ErrNotFound
		}
		return s.putSession(tx, ss, ws)
	})
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
	prev, perr := s.Session(old)
	return s.update(func(tx *bolt.Tx, ws *[]write) error {
		if tx.Bucket(bSessions).Get([]byte(old)) == nil {
			return ErrNotFound // ended meanwhile: no rotation
		}
		if perr == nil {
			_ = del(tx, "user_session", s.Index(prev.User)+"/"+old, ws)
		}
		if err := del(tx, "session", old, ws); err != nil {
			return err
		}
		return s.putSession(tx, nw, ws)
	})
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(hash string) error {
	ss, _ := s.Session(hash)
	return s.update(func(tx *bolt.Tx, ws *[]write) error {
		if ss.User != "" {
			_ = del(tx, "user_session", s.Index(ss.User)+"/"+hash, ws)
		}
		return del(tx, "session", hash, ws)
	})
}

// RevokeUser removes every session of user; it returns how many.
func (s *Store) RevokeUser(user string) (int, error) {
	pfx := []byte(s.Index(user) + "/")
	n := 0
	err := s.update(func(tx *bolt.Tx, ws *[]write) error {
		n = 0
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
			_ = del(tx, "session", string(h), ws)
			_ = del(tx, "user_session", string(k), ws)
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

// Migrate seals the credentials kept under this node's keys (before zone
// sync) again under the zone keys of this store: the envelope under the new
// inside key, each credential under its account's zone key, filed under the
// new index; the old per-account node key is destroyed. Sessions sealed
// under the old key are dropped (people sign in again). It returns how many
// credentials moved and how many sessions were dropped.
func (s *Store) Migrate(ctx context.Context, oldInside []byte, old Keys) (moved, dropped int, err error) {
	olds, err := heain.NewSealer(oldInside)
	if err != nil {
		return 0, 0, err
	}
	all, err := s.All("credential")
	if err != nil {
		return 0, 0, err
	}
	for ix, v := range all {
		if _, err := s.inside.Open(v, []byte("credenv/"+ix)); err == nil {
			continue // already under the zone key
		}
		envRaw, err := olds.Open(v, []byte("credenv/"+ix))
		if err != nil {
			continue // neither key opens it: left as it is
		}
		var env credEnvelope
		if err := json.Unmarshal(envRaw, &env); err != nil {
			return moved, dropped, err
		}
		ks, err := old.Sealer(ctx, env.Key)
		if err != nil {
			return moved, dropped, fmt.Errorf("old credential key: %w", err)
		}
		raw, err := ks.Open(env.Sealed, []byte("cred/"+ix))
		if err != nil {
			return moved, dropped, err
		}
		var c Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			return moved, dropped, err
		}
		if err := s.CreateCredential(ctx, c); err != nil {
			return moved, dropped, err
		}
		if nix := s.Index(c.User); nix != ix {
			if err := s.update(func(tx *bolt.Tx, ws *[]write) error { return del(tx, "credential", ix, ws) }); err != nil {
				return moved, dropped, err
			}
		}
		_ = old.Destroy(ctx, env.Key)
		moved++
	}
	sess, _ := s.All("session")
	us, _ := s.All("user_session")
	err = s.update(func(tx *bolt.Tx, ws *[]write) error {
		gone := map[string]bool{}
		for h, v := range sess {
			if _, err := s.inside.Open(v, []byte("session/"+h)); err == nil {
				continue
			}
			gone[h] = true
			if err := del(tx, "session", h, ws); err != nil {
				return err
			}
			dropped++
		}
		for k := range us {
			if i := strings.LastIndex(k, "/"); i > 0 && (gone[k[i+1:]] || tx.Bucket(bSessions).Get([]byte(k[i+1:])) == nil) {
				if err := del(tx, "user_session", k, ws); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return moved, dropped, err
}
