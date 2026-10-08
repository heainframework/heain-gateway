// Package replica is heain-gateway's change log for zone sync (Stage B-1c,
// author decisions 2026-10-08: sessions and credentials shared by the
// gateways of a zone, with the same mechanism as heain-database; this file
// is the same as heain-database's internal/replica).
//
// Every gateway seals its records under zone keys (heain-sdk App.ZoneKey),
// so a record and its blinded key are the same bytes on every node and can
// be copied without being opened. Each write is recorded here; every
// gateway pulls the others' logs (heain-sdk zonesync, GET
// /v1/gateway/replica/changes) and applies what is newer: last writer wins,
// by the write's time and then its origin. Applied changes are logged
// again, so a gateway that joins later, or was cut off, also gets what came
// from one that is gone. Peers are found with zone discovery only.
package replica

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/heainframework/heain-sdk/zonesync"
)

// Target is one replicated store: it writes a sealed value as it is.
type Target interface {
	// ApplyRaw stores sealed under the blinded key (nil = delete).
	ApplyRaw(key string, sealed []byte) error
}

// Change is one write (heain-sdk zonesync carries it between instances).
type Change = zonesync.Change

type version struct {
	TS     int64  `json:"ts"`
	Origin string `json:"origin"`
}

var (
	bChanges  = []byte("changes")
	bVersions = []byte("versions")
	bCursors  = []byte("cursors")
	bMeta     = []byte("meta")
)

// Log is the local change log.
type Log struct {
	db      *bolt.DB
	self    string
	epoch   string
	mu      sync.Mutex
	last    int64
	targets map[string]Target
}

// Open opens (or creates) the log at path. Writes made here carry the
// log's epoch as their origin (unique per log, also when instance ids repeat
// across nodes).
func Open(path string) (*Log, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("replica: open %s: %w", path, err)
	}
	l := &Log{db: db, targets: map[string]Target{}}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bChanges, bVersions, bCursors, bMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		m := tx.Bucket(bMeta)
		if e := m.Get([]byte("epoch")); e != nil {
			l.epoch = string(e)
			return nil
		}
		r := make([]byte, 8)
		_, _ = rand.Read(r)
		l.epoch = hex.EncodeToString(r)
		return m.Put([]byte("epoch"), []byte(l.epoch))
	})
	l.self = l.epoch
	if err != nil {
		db.Close()
		return nil, err
	}
	return l, nil
}

// Close closes the log.
func (l *Log) Close() error { return l.db.Close() }

// Epoch identifies this log; a peer whose epoch changes (its log was
// recreated) is read again from the start.
func (l *Log) Epoch() string { return l.epoch }

// Register names a replicated store.
func (l *Log) Register(store string, t Target) { l.targets[store] = t }

func u64(n uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }

func (l *Log) append(tx *bolt.Tx, c Change) error {
	b := tx.Bucket(bChanges)
	seq, err := b.NextSequence()
	if err != nil {
		return err
	}
	c.Seq = seq
	raw, _ := json.Marshal(c)
	if err := b.Put(u64(seq), raw); err != nil {
		return err
	}
	v, _ := json.Marshal(version{TS: c.TS, Origin: c.Origin})
	return tx.Bucket(bVersions).Put([]byte(c.Store+"/"+c.Key), v)
}

// Record logs a local write of store's key (sealed nil = delete).
func (l *Log) Record(store, key string, sealed []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().UnixNano()
	if ts <= l.last {
		ts = l.last + 1
	}
	l.last = ts
	return l.db.Update(func(tx *bolt.Tx) error {
		return l.append(tx, Change{Store: store, Key: key, Value: sealed, TS: ts, Origin: l.self})
	})
}

// Changes returns up to limit changes after since, and the head sequence.
func (l *Log) Changes(since uint64, limit int) (string, uint64, []Change, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	out := []Change{}
	var head uint64
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bChanges)
		head = b.Sequence()
		c := b.Cursor()
		for k, v := c.Seek(u64(since + 1)); k != nil && len(out) < limit; k, v = c.Next() {
			var ch Change
			if err := json.Unmarshal(v, &ch); err != nil {
				return err
			}
			out = append(out, ch)
		}
		return nil
	})
	return l.epoch, head, out, err
}

type cursor struct {
	Epoch string `json:"epoch"`
	Seq   uint64 `json:"seq"`
}

// Last returns the epoch and sequence last read from peer.
func (l *Log) Last(peer string) (string, uint64) {
	var c cursor
	_ = l.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bCursors).Get([]byte(peer)); v != nil {
			_ = json.Unmarshal(v, &c)
		}
		return nil
	})
	return c.Epoch, c.Seq
}

// Cursor is where to read peer's log from next.
func (l *Log) Cursor(peer, epoch string) uint64 {
	var c cursor
	_ = l.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bCursors).Get([]byte(peer)); v != nil {
			_ = json.Unmarshal(v, &c)
		}
		return nil
	})
	if c.Epoch != epoch {
		return 0
	}
	return c.Seq
}

// ErrUnknownStore is returned for a change to a store not registered here.
var ErrUnknownStore = errors.New("replica: change for an unknown store")

// Apply applies changes read from peer's log (epoch) and moves the cursor.
// It returns how many were newer than what this node holds.
func (l *Log) Apply(peer, epoch string, cs []Change) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	applied := 0
	for _, c := range cs {
		t, ok := l.targets[c.Store]
		if !ok {
			return applied, fmt.Errorf("%w %q", ErrUnknownStore, c.Store)
		}
		newer := true
		_ = l.db.View(func(tx *bolt.Tx) error {
			if v := tx.Bucket(bVersions).Get([]byte(c.Store + "/" + c.Key)); v != nil {
				var cur version
				if json.Unmarshal(v, &cur) == nil {
					newer = c.NewerThan(cur.TS, cur.Origin)
				}
			}
			return nil
		})
		err := l.db.Update(func(tx *bolt.Tx) error {
			if newer {
				if err := t.ApplyRaw(c.Key, c.Value); err != nil {
					return err
				}
				if err := l.append(tx, c); err != nil {
					return err
				}
			}
			raw, _ := json.Marshal(cursor{Epoch: epoch, Seq: c.Seq})
			return tx.Bucket(bCursors).Put([]byte(peer), raw)
		})
		if err != nil {
			return applied, err
		}
		if newer {
			applied++
			if c.TS > l.last {
				l.last = c.TS
			}
		}
	}
	return applied, nil
}

// Compact drops changes a later change of the same record has replaced, so
// the log grows with the records, not with every write. A peer that reads
// past a dropped change still gets the record's latest change.
func (l *Log) Compact() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	err := l.db.Update(func(tx *bolt.Tx) error {
		b, vs := tx.Bucket(bChanges), tx.Bucket(bVersions)
		var dead [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var c Change
			if json.Unmarshal(v, &c) != nil {
				return nil
			}
			var cur version
			if raw := vs.Get([]byte(c.Store + "/" + c.Key)); raw != nil && json.Unmarshal(raw, &cur) == nil {
				if cur.TS != c.TS || cur.Origin != c.Origin {
					dead = append(dead, append([]byte(nil), k...))
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range dead {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		n = len(dead)
		return nil
	})
	return n, err
}
