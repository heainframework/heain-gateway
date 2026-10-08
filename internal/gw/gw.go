// Package gw is heain-gateway's public side: people (web and mobile) sign
// in and reach the app endpoints heain-core exposes (author decisions
// 2026-10-07):
//
//   - built-in accounts (password + TOTP) and OIDC providers; credentials in
//     the gateway's sealed store, the account (who, roles) in heain-database;
//   - a web session is an HttpOnly cookie plus a CSRF token; a mobile client
//     gets an access token (short) and a refresh token (rotated);
//   - /api/{app}/<path> reaches an exposed route (core gateway.exposures):
//     the gateway checks the route's roles and rate, then calls the app over
//     mTLS with a signed user assertion (heain-sdk), and audits the request;
//   - /admin/... manages accounts (role gateway-admin).
package gw

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-gateway/internal/oidc"
	"github.com/heainframework/heain-gateway/internal/ratelimit"
	"github.com/heainframework/heain-gateway/internal/secret"
	"github.com/heainframework/heain-gateway/internal/store"
	"github.com/heainframework/heain-sdk/heain"
)

// AdminRole may manage accounts through /admin/....
const AdminRole = "gateway-admin"

// Account is a person's account record (heain-database).
type Account struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	Roles    []string `json:"roles"`
	Source   string   `json:"source"` // local | oidc:<provider>
	Disabled bool     `json:"disabled,omitempty"`
}

// ErrNoAccount: the directory has no such account.
var ErrNoAccount = errors.New("no such account")

// Directory is where accounts live (heain-database).
type Directory interface {
	Get(ctx context.Context, id string) (Account, error)
	Put(ctx context.Context, a Account) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]Account, error)
}

// Platform is what the gateway needs from heain-core through heain-sdk.
type Platform interface {
	Routes(ctx context.Context) ([]heain.GatewayRoute, uint64, error)
	Client(app, instance string) (*http.Client, error)
	Sign(u heain.UserAssertion) (string, error)
	Audit(ctx context.Context, capability, outcome string, detail map[string]any) error
}

// Config tunes the gateway.
type Config struct {
	SessionTTL     time.Duration // web and mobile: absolute
	IdleTTL        time.Duration // web: without a request
	AccessTTL      time.Duration // mobile access token
	DefaultRate    int           // per person (or address) per route, a minute
	LoginRate      int           // login attempts per address a minute
	LockAfter      int           // failed logins before a lock
	LockFor        time.Duration
	MaxBody        int64
	UpstreamTO     time.Duration
	TrustForwarded bool   // take the client address from X-Forwarded-For (behind a proxy on this host)
	Issuer         string // shown in authenticator apps
	CookieName     string
}

// Defaults fills unset fields.
func (c *Config) Defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&c.SessionTTL, 12*time.Hour)
	set(&c.IdleTTL, 30*time.Minute)
	set(&c.AccessTTL, 15*time.Minute)
	set(&c.LockFor, 15*time.Minute)
	set(&c.UpstreamTO, 60*time.Second)
	if c.DefaultRate <= 0 {
		c.DefaultRate = 120
	}
	if c.LoginRate <= 0 {
		c.LoginRate = 20
	}
	if c.LockAfter <= 0 {
		c.LockAfter = 5
	}
	if c.MaxBody <= 0 {
		c.MaxBody = 32 << 20
	}
	if c.Issuer == "" {
		c.Issuer = "heain"
	}
	if c.CookieName == "" {
		c.CookieName = "heain_session"
	}
}

// Gateway is the public side.
type Gateway struct {
	Cfg       Config
	Store     *store.Store
	Dir       Directory
	Plat      Platform
	Providers map[string]*oidc.Provider
	Logf      func(string, ...any)
	Now       func() time.Time

	limit *ratelimit.Limiter

	rmu       sync.RWMutex
	routes    []heain.GatewayRoute
	routesVer uint64
	routesAt  time.Time
	rr        map[string]int

	pmu     sync.Mutex
	pending map[string]oidcPending
}

// New prepares a gateway.
func New(g *Gateway) *Gateway {
	g.Cfg.Defaults()
	if g.Now == nil {
		g.Now = time.Now
	}
	if g.Logf == nil {
		g.Logf = func(string, ...any) {}
	}
	g.limit = ratelimit.New()
	g.rr = map[string]int{}
	g.pending = map[string]oidcPending{}
	if g.Providers == nil {
		g.Providers = map[string]*oidc.Provider{}
	}
	return g
}

// Handler is the public HTTP handler.
func (g *Gateway) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	m.HandleFunc("POST /auth/login", g.login)
	m.HandleFunc("POST /auth/refresh", g.refresh)
	m.HandleFunc("POST /auth/logout", g.logout)
	m.HandleFunc("GET /auth/me", g.me)
	m.HandleFunc("POST /auth/password", g.changePassword)
	m.HandleFunc("POST /auth/totp/setup", g.totpSetup)
	m.HandleFunc("POST /auth/totp/confirm", g.totpConfirm)
	m.HandleFunc("GET /auth/providers", g.providers)
	m.HandleFunc("GET /auth/oidc/{p}/start", g.oidcStart)
	m.HandleFunc("GET /auth/oidc/{p}/callback", g.oidcCallback)
	m.HandleFunc("GET /admin/users", g.admin(g.adminList))
	m.HandleFunc("POST /admin/users", g.admin(g.adminCreate))
	m.HandleFunc("GET /admin/users/{id}", g.admin(g.adminGet))
	m.HandleFunc("PUT /admin/users/{id}", g.admin(g.adminUpdate))
	m.HandleFunc("DELETE /admin/users/{id}", g.admin(g.adminDelete))
	m.HandleFunc("POST /admin/users/{id}/reset", g.admin(g.adminReset))
	m.HandleFunc("POST /admin/users/{id}/revoke", g.admin(g.adminRevoke))
	m.HandleFunc("GET /admin/routes", g.admin(g.adminRoutes))
	m.HandleFunc("/api/{app}/{rest...}", g.proxy)
	return secHeaders(m)
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Strict-Transport-Security", "max-age=31536000")
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			hd.Set("Referrer-Policy", "no-referrer")
			hd.Set("X-Frame-Options", "DENY")
			hd.Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{"code": errCode, "message": msg}})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "body: "+err.Error())
		return false
	}
	return true
}

// clientAddr is the address the request came from.
func (g *Gateway) clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if g.Cfg.TrustForwarded {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			if f := r.Header.Get("X-Forwarded-For"); f != "" {
				first, _, _ := strings.Cut(f, ",")
				if p := net.ParseIP(strings.TrimSpace(first)); p != nil {
					return p.String()
				}
			}
		}
	}
	return host
}

func (g *Gateway) audit(ctx context.Context, capability, outcome string, d map[string]any) {
	if err := g.Plat.Audit(ctx, capability, outcome, d); err != nil {
		g.Logf("heain-gateway: audit %s %s failed: %v", capability, outcome, err)
	}
}

// --- sessions ---

// principal is the signed-in person of a request.
type principal struct {
	S      store.Session
	Bearer bool
}

func (g *Gateway) tokenOf(r *http.Request) (string, bool) {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(a, "Bearer ")), true
	}
	if c, err := r.Cookie(g.Cfg.CookieName); err == nil && c.Value != "" {
		return c.Value, false
	}
	return "", false
}

// session finds the request's valid session; for a web session, an unsafe
// method also needs the CSRF token. ok=false has written the answer.
func (g *Gateway) session(w http.ResponseWriter, r *http.Request, required bool) (*principal, bool) {
	tok, bearer := g.tokenOf(r)
	if tok == "" {
		if required {
			fail(w, http.StatusUnauthorized, "unauthenticated", "sign in first")
			return nil, false
		}
		return nil, true
	}
	h := secret.SHA256(tok)
	ss, err := g.Store.Session(h)
	now := g.Now()
	if err == nil {
		switch {
		case now.After(ss.Expires):
			err = errors.New("expired")
		case ss.Kind == "web" && bearer, ss.Kind == "mobile" && !bearer:
			err = errors.New("wrong kind")
		case ss.Kind == "web" && now.After(ss.LastSeen.Add(g.Cfg.IdleTTL)):
			err = errors.New("idle")
		case ss.Kind == "mobile" && now.After(ss.AccessExp):
			err = errors.New("access token expired")
		}
		if err != nil && ss.Kind == "web" {
			_ = g.Store.DeleteSession(h)
		}
	}
	if err != nil {
		if bearer {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		fail(w, http.StatusUnauthorized, "unauthenticated", "the session is not valid; sign in again")
		return nil, false
	}
	if !bearer && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if c := r.Header.Get("X-CSRF-Token"); c == "" || c != ss.CSRF {
			fail(w, http.StatusForbidden, "csrf", "X-CSRF-Token is missing or wrong")
			return nil, false
		}
	}
	if ss.Kind == "web" && now.Sub(ss.LastSeen) > time.Minute {
		ss.LastSeen = now
		_ = g.Store.PutSession(ss)
	}
	return &principal{S: ss, Bearer: bearer}, true
}

// newSession creates a session for acc and answers the client.
func (g *Gateway) newSession(w http.ResponseWriter, r *http.Request, acc Account, amr, kind string) store.Session {
	now := g.Now()
	tok := secret.Token(32)
	ss := sessionFor(acc, amr, kind, now, g.Cfg.SessionTTL, g.clientAddr(r))
	ss.Hash = secret.SHA256(tok)
	out := map[string]any{"user": acc.ID, "name": acc.Name, "roles": acc.Roles, "amr": amr, "session": ss.ID, "expires": ss.Expires}
	if kind == "mobile" {
		ref := secret.Token(32)
		ss.AccessExp, ss.RefreshH = now.Add(g.Cfg.AccessTTL), secret.SHA256(ref)
		out["access_token"], out["refresh_token"], out["token_type"] = tok, ref, "Bearer"
		out["expires_in"] = int(g.Cfg.AccessTTL.Seconds())
	} else {
		ss.CSRF = secret.Token(24)
		g.setSessionCookies(w, tok, ss)
		out["csrf_token"] = ss.CSRF
	}
	if err := g.Store.CreateSession(ss); err != nil {
		fail(w, http.StatusInternalServerError, "internal", "session store: "+err.Error())
		return ss
	}
	writeJSON(w, http.StatusOK, out)
	return ss
}

func sessionFor(acc Account, amr, kind string, now time.Time, ttl time.Duration, addr string) store.Session {
	return store.Session{User: acc.ID, Name: acc.Name, Roles: acc.Roles, AMR: amr, Kind: kind,
		ID: heain.NewID(), Created: now, LastSeen: now, Expires: now.Add(ttl), ClientAddr: addr}
}

// setSessionCookies sets the HttpOnly session cookie (SameSite=Lax, so the
// first page after an OIDC redirect has it; unsafe methods also need the
// CSRF token) and a readable heain_csrf cookie for the web app.
func (g *Gateway) setSessionCookies(w http.ResponseWriter, tok string, ss store.Session) {
	http.SetCookie(w, &http.Cookie{Name: g.Cfg.CookieName, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, Expires: ss.Expires})
	http.SetCookie(w, &http.Cookie{Name: "heain_csrf", Value: ss.CSRF, Path: "/", Secure: true, SameSite: http.SameSiteLaxMode, Expires: ss.Expires})
}

// Sweep removes expired sessions and OIDC logins now and then.
func (g *Gateway) Sweep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := g.Store.Sweep(g.Now()); n > 0 {
				g.Logf("heain-gateway: %d expired session(s) removed", n)
			}
			g.pmu.Lock()
			for k, p := range g.pending {
				if g.Now().After(p.Exp) {
					delete(g.pending, k)
				}
			}
			g.pmu.Unlock()
		}
	}
}

func hasAnyRole(have, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}
