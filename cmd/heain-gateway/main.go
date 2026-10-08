// Command heain-gateway is the way in for people (web and mobile) to the
// apps of a heain deployment. It is configured through the heain-sdk HEAIN_*
// variables (heain.StartFromEnv) plus the flags below, and runs however the
// operator likes: a plain process, a service unit, or a container.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/heainframework/heain-gateway/internal/directory"
	"github.com/heainframework/heain-gateway/internal/gw"
	"github.com/heainframework/heain-gateway/internal/oidc"
	"github.com/heainframework/heain-gateway/internal/store"
	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-sdk/zonesync"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// platform adapts heain-sdk's App to gw.Platform.
type platform struct{ app *heain.App }

func (p platform) Routes(ctx context.Context) ([]heain.GatewayRoute, uint64, error) {
	return p.app.GatewayRoutes(ctx)
}
func (p platform) Client(app, inst string) (*http.Client, error) { return p.app.AppClient(app, inst) }
func (p platform) Sign(u heain.UserAssertion) (string, error)    { return p.app.SignUserAssertion(u) }
func (p platform) Audit(ctx context.Context, c, o string, d map[string]any) error {
	return p.app.Audit(ctx, c, o, d)
}

// selfSignedPair is a throwaway certificate for 127.0.0.1 and localhost.
func selfSignedPair() (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "heain-gateway (test)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

func main() {
	pubListen := flag.String("public-listen", env("HEAIN_GATEWAY_PUBLIC_LISTEN", ":8443"), "where people connect (HTTPS)")
	pubCert := flag.String("public-cert", os.Getenv("HEAIN_GATEWAY_PUBLIC_CERT"), "the public HTTPS certificate (PEM, chain)")
	pubKey := flag.String("public-key", os.Getenv("HEAIN_GATEWAY_PUBLIC_KEY"), "its private key (PEM)")
	oidcFile := flag.String("oidc-config", os.Getenv("HEAIN_GATEWAY_OIDC_CONFIG"), "OIDC providers (JSON list); secrets come from the variables it names")
	bootstrap := flag.String("bootstrap-admin", os.Getenv("HEAIN_GATEWAY_BOOTSTRAP_ADMIN"), "with no account yet: create this gateway-admin with a one-time password written to <state>/bootstrap-admin.txt")
	sessionTTL := flag.Duration("session-ttl", 12*time.Hour, "a session's absolute lifetime")
	idleTTL := flag.Duration("idle-ttl", 30*time.Minute, "a web session ends after this long without a request")
	accessTTL := flag.Duration("access-ttl", 15*time.Minute, "a mobile access token's lifetime")
	rate := flag.Int("default-rate", 120, "requests a minute per person (or address) per route, when the route sets none")
	loginRate := flag.Int("login-rate", 20, "sign-in attempts a minute per address")
	maxBody := flag.Int64("max-body", 32<<20, "largest request body passed on")
	upstream := flag.Duration("upstream-timeout", 60*time.Second, "how long an app may take to answer")
	trustFwd := flag.Bool("trust-forwarded", false, "take the client address from X-Forwarded-For (only from a proxy on this host)")
	routesEvery := flag.Duration("routes-refresh", 5*time.Second, "how often the routes are read from core")
	selfSigned := flag.Bool("test-self-signed", false, "TEST ONLY: without -public-cert, serve people with a throwaway self-signed certificate (127.0.0.1, localhost)")
	issuer := flag.String("totp-issuer", env("HEAIN_GATEWAY_TOTP_ISSUER", "heain"), "the name authenticator apps show")
	zoneSync := flag.Bool("zone-sync", env("HEAIN_GATEWAY_ZONE_SYNC", "on") != "off", "share credentials and sessions with the other gateways of the zone, sealed under zone keys (env HEAIN_GATEWAY_ZONE_SYNC=off to keep them on this instance only)")
	zoneEvery := flag.Duration("zone-sync-every", 2*time.Second, "how often the other gateways of the zone are read (a revocation is pushed at once)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var pair tls.Certificate
	var err error
	switch {
	case *pubCert != "" && *pubKey != "":
		if pair, err = tls.LoadX509KeyPair(*pubCert, *pubKey); err != nil {
			log.Fatalf("heain-gateway: public certificate: %v", err)
		}
	case *selfSigned:
		if pair, err = selfSignedPair(); err != nil {
			log.Fatal(err)
		}
		log.Printf("heain-gateway: WARNING -test-self-signed (TEST ONLY): people are served with a throwaway self-signed certificate")
	default:
		log.Fatal("heain-gateway: -public-cert and -public-key are required (people connect over HTTPS)")
	}
	var provCfgs []oidc.Config
	if *oidcFile != "" {
		if provCfgs, err = oidc.LoadConfigs(*oidcFile); err != nil {
			log.Fatalf("heain-gateway: %v", err)
		}
	}

	state := env("HEAIN_STATE_DIR", "/state")
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	log.Printf("heain-gateway: registered (%s), waiting for admission", app.Status())
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	inside, err := app.DataKey(ctx, "inside")
	if err != nil {
		log.Fatalf("heain-gateway: data key from core: %v", err)
	}
	var st *store.Store
	var zs *zoneSyncer
	if *zoneSync {
		// Stage B-1c: credentials and sessions under zone keys, shared by the
		// gateways of the zone (author decisions 2026-10-08).
		zk, err := zoneKey(ctx, app, "gateway")
		if err != nil {
			log.Fatalf("heain-gateway: zone key from core: %v", err)
		}
		if st, err = store.Open(filepath.Join(state, "gateway.db"), zk, store.Keys{Sealer: app.ZoneSealer, Destroy: app.DestroyZoneKey}); err != nil {
			log.Fatal(err)
		}
		if zs, err = startZoneSync(ctx, app, st, state, inside); err != nil {
			log.Fatal(err)
		}
		defer zs.log.Close()
	} else if st, err = store.Open(filepath.Join(state, "gateway.db"), inside, store.Keys{Sealer: app.Sealer, Destroy: app.DestroyDataKey}); err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	provs := map[string]*oidc.Provider{}
	for _, c := range provCfgs {
		var p *oidc.Provider
		for i := 0; ; i++ {
			if p, err = oidc.Discover(ctx, c); err == nil || i == 10 || ctx.Err() != nil {
				break
			}
			time.Sleep(3 * time.Second)
		}
		if err != nil {
			log.Fatalf("heain-gateway: %v", err)
		}
		provs[c.Name] = p
		log.Printf("heain-gateway: OIDC provider %s (%s)", c.Name, c.Issuer)
	}

	g := gw.New(&gw.Gateway{Store: st, Dir: directory.DB{App: app}, Plat: platform{app}, Providers: provs, Logf: log.Printf,
		Cfg: gw.Config{SessionTTL: *sessionTTL, IdleTTL: *idleTTL, AccessTTL: *accessTTL, DefaultRate: *rate, LoginRate: *loginRate,
			MaxBody: *maxBody, UpstreamTO: *upstream, TrustForwarded: *trustFwd, Issuer: *issuer}})

	if zs != nil {
		// another gateway of the zone may already hold the accounts
		if n, _, err := zs.puller.Once(ctx); err == nil && n > 0 {
			log.Printf("heain-gateway: zone sync: %d record(s) from the other gateways of the zone", n)
		}
	}
	if *bootstrap != "" && !st.HasCredentials() {
		if !gw.UserRe.MatchString(*bootstrap) {
			log.Fatalf("heain-gateway: -bootstrap-admin %q is not an account name", *bootstrap)
		}
		var temp string
		for i := 0; ; i++ { // heain-database may still be starting
			if temp, err = g.CreateLocal(ctx, *bootstrap, "", []string{gw.AdminRole}, ""); err == nil || i == 20 || ctx.Err() != nil {
				break
			}
			time.Sleep(3 * time.Second)
		}
		if err != nil {
			log.Fatalf("heain-gateway: bootstrap admin: %v", err)
		}
		f := filepath.Join(state, "bootstrap-admin.txt")
		if err := os.WriteFile(f, []byte(*bootstrap+" "+temp+"\n"), 0o600); err != nil {
			log.Fatal(err)
		}
		_ = app.Audit(ctx, "gateway.auth", "admin", map[string]any{"op": "bootstrap", "target": *bootstrap})
		log.Printf("heain-gateway: bootstrap admin %s created; its one-time password is in %s (change it at the first sign-in)", *bootstrap, f)
	}

	if err := g.RefreshRoutes(ctx); err != nil {
		log.Printf("heain-gateway: routes from core: %v (is heain-gateway listed in core's gateway.apps?)", err)
	}
	go g.WatchRoutes(ctx, *routesEvery)
	go g.Sweep(ctx, time.Minute)

	// the app plane (mTLS, for other apps)
	srv := app.NewServer()
	must := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	must(srv.HandleFunc("GET /v1/gateway/routes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.RoutesView())
	}))
	must(srv.HandleFunc("POST /v1/gateway/sessions/revoke", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			User string `json:"user"`
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&q); err != nil || q.User == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "bad_request", "message": `body: {"user": "<account id>"}`}})
			return
		}
		n, err := st.RevokeUser(q.User)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Printf("heain-gateway: %s ended %d session(s) of %s", heain.Caller(r.Context()), n, q.User)
		_ = json.NewEncoder(w).Encode(map[string]any{"user": q.User, "sessions_ended": n})
	}))
	if zs != nil {
		must(srv.HandleFunc("GET /v1/gateway/replica/changes", zonesync.Handler(app, zs.log)))
		must(srv.HandleFunc("POST /v1/gateway/replica/poke", zs.puller.PokeHandler()))
		go zs.run(ctx, *zoneEvery)
	} else {
		off := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			code, msg := http.StatusServiceUnavailable, "zone sync is off on this instance"
			if !zonesync.SameApp(app, r) {
				code, msg = http.StatusForbidden, "only another heain-gateway may ask"
			}
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "zone_sync_off", "message": msg}})
		}
		must(srv.HandleFunc("GET /v1/gateway/replica/changes", off))
		must(srv.HandleFunc("POST /v1/gateway/replica/poke", off))
	}
	al, err := net.Listen("tcp", heain.Listen(":19500"))
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := srv.Serve(ctx, al); err != nil && ctx.Err() == nil {
			log.Fatal(err)
		}
	}()

	// the public side (HTTPS, for people)
	pub := &http.Server{Addr: *pubListen, Handler: g.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}}
	pl, err := net.Listen("tcp", *pubListen)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = pub.Shutdown(sctx)
	}()
	log.Printf("heain-gateway: active; people on https://%s, apps on %s (%d OIDC provider(s))", pl.Addr(), al.Addr(), len(provs))
	if err := pub.ServeTLS(pl, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
	log.Printf("heain-gateway: deregistered")
}
