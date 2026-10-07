// Command demo-app is an example app behind heain-gateway: it declares
// public endpoints and answers with the person heain-sdk verified
// (heain.UserOf). It checks one data-level right itself: only the person
// who created an item may delete it (author decision 4: fine-grained rights
// are the app's).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/heainframework/heain-sdk/heain"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	owner := map[string]string{}
	who := func(r *http.Request) map[string]any {
		u := heain.UserOf(r.Context())
		if u == nil {
			return map[string]any{"user": nil}
		}
		return map[string]any{"user": u.ID, "name": u.Name, "roles": u.Roles, "amr": u.AuthMethod, "gateway": u.Gateway, "session": u.Session}
	}
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	srv := app.NewServer()
	must := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	must(srv.HandleFunc("GET /v1/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		out := who(r)
		out["item"], out["query"] = r.PathValue("id"), r.URL.RawQuery
		reply(w, 200, out)
	}))
	must(srv.HandleFunc("POST /v1/items", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var q struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(b, &q)
		u := heain.UserOf(r.Context())
		if u == nil || q.ID == "" {
			reply(w, 400, map[string]any{"error": map[string]any{"code": "bad_request", "message": "a person and an id"}})
			return
		}
		mu.Lock()
		owner[q.ID] = u.ID
		mu.Unlock()
		out := who(r)
		out["created"] = q.ID
		reply(w, 200, out)
	}))
	must(srv.HandleFunc("DELETE /v1/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		u := heain.UserOf(r.Context())
		mu.Lock()
		o := owner[r.PathValue("id")]
		mu.Unlock()
		if u == nil || o != u.ID {
			reply(w, 403, map[string]any{"error": map[string]any{"code": "not_yours", "message": "only the person who created it may delete it"}})
			return
		}
		mu.Lock()
		delete(owner, r.PathValue("id"))
		mu.Unlock()
		reply(w, 200, map[string]any{"deleted": r.PathValue("id"), "user": u.ID})
	}))
	must(srv.HandleFunc("GET /v1/internal", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, who(r)) }))
	must(srv.HandleFunc("GET /v1/hello", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, who(r)) }))
	l, err := net.Listen("tcp", heain.Listen(":19510"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("demo-app: active on %s", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
}
