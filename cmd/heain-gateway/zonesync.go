package main

// Stage B-1c (author decisions 2026-10-08): the gateways of a zone share
// credentials and sessions with the same mechanism as heain-database --
// records sealed under zone keys, change logs pulled between instances
// (heain-sdk zonesync), last writer wins -- and a revocation (any deleted
// session or credential) is pushed at once: the other gateways are asked
// to pull now.

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"time"

	"github.com/heainframework/heain-gateway/internal/replica"
	"github.com/heainframework/heain-gateway/internal/store"
	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-sdk/zonesync"
)

const capReplica = "gateway.replica"

type zoneSyncer struct {
	app    *heain.App
	log    *replica.Log
	puller *zonesync.Puller
	poke   chan struct{}
}

// zoneKey asks core for zone key name, waiting while the zone's custodian
// cannot be reached and this node holds no copy yet.
func zoneKey(ctx context.Context, app *heain.App, name string) ([]byte, error) {
	for {
		k, err := app.ZoneKey(ctx, name)
		if err == nil {
			return k, nil
		}
		var ce *core.Error
		if !errors.As(err, &ce) || !ce.Retryable {
			return nil, err
		}
		log.Printf("heain-gateway: zone key not available yet (%v); retrying", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func startZoneSync(ctx context.Context, app *heain.App, st *store.Store, state string, nodeInside []byte) (*zoneSyncer, error) {
	moved, dropped, err := st.Migrate(ctx, nodeInside, store.Keys{Sealer: app.Sealer, Destroy: app.DestroyDataKey})
	if err != nil {
		return nil, err
	}
	if moved+dropped > 0 {
		log.Printf("heain-gateway: zone sync: %d credential(s) sealed again under zone keys, %d session(s) under the node key ended (sign in again)", moved, dropped)
	}
	rlog, err := replica.Open(filepath.Join(state, "replica.db"))
	if err != nil {
		return nil, err
	}
	stores := []string{"credential", "session", "user_session"}
	for _, n := range stores {
		rlog.Register(n, st.Target(n))
	}
	if _, head, _, err := rlog.Changes(0, 1); err == nil && head == 0 {
		for _, n := range stores {
			all, err := st.All(n)
			if err != nil {
				return nil, err
			}
			for k, v := range all {
				if err := rlog.Record(n, k, v); err != nil {
					return nil, err
				}
			}
		}
	}
	z := &zoneSyncer{app: app, log: rlog, poke: make(chan struct{}, 1)}
	z.puller = &zonesync.Puller{App: app, Log: rlog, Capability: capReplica, Path: "/v1/gateway/replica/changes",
		PokePath: "/v1/gateway/replica/poke", Logf: log.Printf,
		Audit: func(ctx context.Context, peer string, n int) {
			_ = app.Audit(ctx, capReplica, "applied", map[string]any{"peer": peer, "changes": n})
		}}
	st.OnWrite = func(storeName, key string, sealed []byte) {
		if err := rlog.Record(storeName, key, sealed); err != nil {
			log.Printf("heain-gateway: zone sync: logging a write: %v", err)
		}
		if sealed == nil && storeName != "user_session" {
			select { // a session ended or a credential removed: tell the others now
			case z.poke <- struct{}{}:
			default:
			}
		}
	}
	log.Printf("heain-gateway: zone sync on (epoch %s): credentials and sessions are shared by the gateways of the zone", rlog.Epoch())
	return z, nil
}

func (z *zoneSyncer) run(ctx context.Context, every time.Duration) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-z.poke:
				time.Sleep(100 * time.Millisecond) // gather a burst (a revoke of many sessions)
				pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				n := z.puller.Poke(pctx)
				cancel()
				log.Printf("heain-gateway: zone sync: a revocation was pushed (%d gateway(s) asked to pull now)", n)
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Hour):
			}
			if n, err := z.log.Compact(); err == nil && n > 0 {
				log.Printf("heain-gateway: zone sync: %d replaced change(s) compacted", n)
			}
		}
	}()
	z.puller.Run(ctx, every)
}
