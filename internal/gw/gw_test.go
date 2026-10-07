package gw

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heainframework/heain-gateway/internal/oidc"
	"github.com/heainframework/heain-gateway/internal/oidc/fakeidp"
	"github.com/heainframework/heain-gateway/internal/secret"
	"github.com/heainframework/heain-gateway/internal/store"
	"github.com/heainframework/heain-gateway/internal/totp"
	"github.com/heainframework/heain-sdk/heain"
)

type memDir struct {
	mu sync.Mutex
	m  map[string]Account
}

func (d *memDir) Get(_ context.Context, id string) (Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.m[id]
	if !ok {
		return Account{}, ErrNoAccount
	}
	return a, nil
}
func (d *memDir) Put(_ context.Context, a Account) error {
	d.mu.Lock()
	d.m[a.ID] = a
	d.mu.Unlock()
	return nil
}
func (d *memDir) Delete(_ context.Context, id string) error {
	d.mu.Lock()
	delete(d.m, id)
	d.mu.Unlock()
	return nil
}
func (d *memDir) List(context.Context) ([]Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var l []Account
	for _, a := range d.m {
		l = append(l, a)
	}
	return l, nil
}

type fakePlat struct {
	mu     sync.Mutex
	routes []heain.GatewayRoute
	events []string
	up     *httptest.Server
}

func (p *fakePlat) Routes(context.Context) ([]heain.GatewayRoute, uint64, error) {
	return p.routes, 3, nil
}
func (p *fakePlat) Client(app, inst string) (*http.Client, error) { return p.up.Client(), nil }
func (p *fakePlat) Sign(u heain.UserAssertion) (string, error) {
	b, _ := json.Marshal(u)
	return string(b), nil
}
func (p *fakePlat) Audit(_ context.Context, c, o string, d map[string]any) error {
	p.mu.Lock()
	p.events = append(p.events, c+" "+o+" "+toS(d["user"]))
	p.mu.Unlock()
	return nil
}
func (p *fakePlat) has(s string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.events {
		if strings.HasPrefix(e, s) {
			return true
		}
	}
	return false
}

func toS(v any) string { s, _ := v.(string); return s }

type kms struct{ m map[string][]byte }

func (k *kms) sealer(_ context.Context, n string) (*heain.Sealer, error) {
	if _, ok := k.m[n]; !ok {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		k.m[n] = b
	}
	return heain.NewSealer(k.m[n])
}
func (k *kms) destroy(_ context.Context, n string) error { delete(k.m, n); return nil }

type env struct {
	g    *Gateway
	srv  *httptest.Server
	dir  *memDir
	plat *fakePlat
	now  time.Time
	mu   sync.Mutex
	idp  *fakeidp.IdP
}

func (e *env) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

func setup(t *testing.T) *env {
	secret.Iterations = 1000
	e := &env{now: time.Now(), dir: &memDir{m: map[string]Account{}}}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "evil=1")
		_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path, "query": r.URL.RawQuery, "user": r.Header.Get(heain.HeaderUser),
			"lane": r.Header.Get(heain.HeaderLane), "trace": r.Header.Get(heain.HeaderTrace), "body": string(b), "cookie": r.Header.Get("Cookie")})
	}))
	t.Cleanup(up.Close)
	inst := []heain.GatewayInstance{{InstanceID: "a1", EndpointBase: up.URL}}
	e.plat = &fakePlat{up: up, routes: []heain.GatewayRoute{
		{App: "demo", Method: "GET", Path: "/v1/items/{id}", Roles: []string{"clerk", "manager"}, Auth: "user", Status: "ok", Lane: "records", Instances: inst},
		{App: "demo", Method: "POST", Path: "/v1/items", Roles: []string{"clerk"}, Auth: "user", Status: "ok", Instances: inst},
		{App: "demo", Method: "DELETE", Path: "/v1/items/{id}", Roles: []string{"manager"}, Auth: "user", Status: "ok", Instances: inst},
		{App: "demo", Method: "GET", Path: "/v1/hello", Auth: "anonymous", Status: "ok", RatePerMin: 3, Instances: inst},
		{App: "demo", Method: "GET", Path: "/v1/down", Auth: "user", Status: "no_instance", Instances: []heain.GatewayInstance{}},
	}}
	k := &kms{m: map[string][]byte{}}
	inside := make([]byte, 32)
	_, _ = rand.Read(inside)
	st, err := store.Open(filepath.Join(t.TempDir(), "gw.db"), inside, store.Keys{Sealer: k.sealer, Destroy: k.destroy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e.idp = fakeidp.New("gw", "idp-secret")
	is := httptest.NewServer(e.idp)
	t.Cleanup(is.Close)
	e.idp.Issuer = is.URL
	os.Setenv("GW_TEST_IDP_SECRET", "idp-secret")
	e.g = New(&Gateway{Store: st, Dir: e.dir, Plat: e.plat, Now: e.clock, Logf: t.Logf, Providers: map[string]*oidc.Provider{}})
	e.srv = httptest.NewTLSServer(e.g.Handler())
	t.Cleanup(e.srv.Close)
	p, err := oidc.Discover(context.Background(), oidc.Config{Name: "corp", Issuer: is.URL, ClientID: "gw", ClientSecretEnv: "GW_TEST_IDP_SECRET",
		RedirectURL: e.srv.URL + "/auth/oidc/corp/callback", AutoCreate: true, DefaultRoles: []string{"clerk"}})
	if err != nil {
		t.Fatal(err)
	}
	e.g.Providers["corp"] = p
	if err := e.g.RefreshRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

// client is a browser (cookie jar) or a bare client.
type client struct {
	t    *testing.T
	e    *env
	hc   *http.Client
	csrf string
	bear string
}

func (e *env) browser(t *testing.T) *client {
	jar, _ := cookiejar.New(nil)
	base := e.srv.Client()
	hc := &http.Client{Transport: base.Transport, Jar: jar}
	return &client{t: t, e: e, hc: hc}
}

func (c *client) do(method, path string, body any, hdr ...string) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.bear != "" {
		req.Header.Set("Authorization", "Bearer "+c.bear)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (c *client) csrfDo(method, path string, body any) (int, map[string]any) {
	return c.do(method, path, body, "X-CSRF-Token", c.csrf)
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	return toS(e["code"])
}

func (c *client) login(user, pw string, extra map[string]any) (int, map[string]any) {
	body := map[string]any{"username": user, "password": pw}
	for k, v := range extra {
		body[k] = v
	}
	code, out := c.do("POST", "/auth/login", body)
	if code == 200 {
		c.csrf = toS(out["csrf_token"])
		if a := toS(out["access_token"]); a != "" {
			c.bear = a
		}
	}
	return code, out
}

func TestWebSessionAndProxy(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.g.CreateLocal(ctx, "clerk1", "Somchai", []string{"clerk"}, "clerk-password-1"); err != nil {
		t.Fatal(err)
	}
	b := e.browser(t)
	if code, out := b.login("clerk1", "wrong-password-x", nil); code != 401 || errCode(out) != "invalid_credentials" {
		t.Fatalf("wrong password: %d %v", code, out)
	}
	if code, out := b.login("nobody", "whatever-password", nil); code != 401 || errCode(out) != "invalid_credentials" {
		t.Fatalf("unknown user: %d %v", code, out)
	}
	if code, out := b.login("clerk1", "clerk-password-1", nil); code != 200 || b.csrf == "" || out["access_token"] != nil {
		t.Fatalf("login: %d %v", code, out)
	}
	if code, out := b.do("GET", "/auth/me", nil); code != 200 || out["user"] != "clerk1" || out["amr"] != "pwd" {
		t.Fatalf("me: %d %v", code, out)
	}
	// a user route, with the assertion
	code, out := b.do("GET", "/api/demo/v1/items/42?x=1", nil, "Cookie", "ignored=1")
	if code != 200 || out["path"] != "/v1/items/42" || out["query"] != "x=1" || out["lane"] != "records" || out["cookie"] != "" {
		t.Fatalf("proxy: %d %v", code, out)
	}
	var ua heain.UserAssertion
	_ = json.Unmarshal([]byte(toS(out["user"])), &ua)
	if ua.Subject != "clerk1" || ua.Audience != "demo" || ua.Path != "/v1/items/42" || ua.Method != "GET" || ua.Trace != out["trace"] || ua.Roles[0] != "clerk" || ua.Session == "" {
		t.Fatalf("assertion: %+v", ua)
	}
	if !e.plat.has("gateway.proxy ok clerk1") {
		t.Fatalf("proxy audit: %v", e.plat.events)
	}
	// unsafe methods need the CSRF token
	if code, out := b.do("POST", "/api/demo/v1/items", map[string]any{"a": 1}); code != 403 || errCode(out) != "csrf" {
		t.Fatalf("no csrf: %d %v", code, out)
	}
	if code, out := b.csrfDo("POST", "/api/demo/v1/items", map[string]any{"a": 1}); code != 200 || out["body"] != `{"a":1}` {
		t.Fatalf("post: %d %v", code, out)
	}
	if code, _ := b.csrfDo("DELETE", "/api/demo/v1/items/42", nil); code != 403 {
		t.Fatal("manager-only route")
	}
	if code, _ := b.do("GET", "/api/demo/v1/nothing", nil); code != 404 {
		t.Fatal("unknown route")
	}
	if code, _ := b.do("GET", "/api/other/v1/items/1", nil); code != 404 {
		t.Fatal("unknown app")
	}
	if code, _ := b.do("GET", "/api/demo/v1/down", nil); code != 503 {
		t.Fatal("route without instance")
	}
	// anonymous: no session needed, no assertion; rate 3/min
	anon := e.browser(t)
	for i := 0; i < 3; i++ {
		if code, out := anon.do("GET", "/api/demo/v1/hello", nil); code != 200 || out["user"] != "" {
			t.Fatalf("anonymous %d: %d %v", i, code, out)
		}
	}
	if code, out := anon.do("GET", "/api/demo/v1/hello", nil); code != 429 || errCode(out) != "rate_limited" {
		t.Fatalf("rate: %d %v", code, out)
	}
	if code, _ := anon.do("GET", "/api/demo/v1/items/1", nil); code != 401 {
		t.Fatal("a user route without a session")
	}
	// idle web session ends
	e.advance(31 * time.Minute)
	if code, _ := b.do("GET", "/auth/me", nil); code != 401 {
		t.Fatal("idle session must end")
	}
	// logout
	b.login("clerk1", "clerk-password-1", nil)
	if code, _ := b.csrfDo("POST", "/auth/logout", nil); code != 200 {
		t.Fatal("logout")
	}
	if code, _ := b.do("GET", "/auth/me", nil); code != 401 {
		t.Fatal("after logout")
	}
}

func TestLockTOTPAndPasswordChange(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	temp, err := e.g.CreateLocal(ctx, "nida", "Nida", []string{"clerk"}, "")
	if err != nil || temp == "" {
		t.Fatal("temporary password")
	}
	b := e.browser(t)
	if code, out := b.login("nida", temp, nil); code != 403 || errCode(out) != "password_change_required" {
		t.Fatalf("must change: %d %v", code, out)
	}
	if code, out := b.login("nida", temp, map[string]any{"new_password": "nida"}); code != 400 || errCode(out) != "weak_password" {
		t.Fatalf("weak: %d %v", code, out)
	}
	if code, _ := b.login("nida", temp, map[string]any{"new_password": "a much better password"}); code != 200 {
		t.Fatal("changed at first sign-in")
	}
	// TOTP
	code, out := b.csrfDo("POST", "/auth/totp/setup", map[string]any{"password": "a much better password"})
	sec := toS(out["secret"])
	if code != 200 || sec == "" || !strings.HasPrefix(toS(out["otpauth_uri"]), "otpauth://totp/") {
		t.Fatalf("setup: %d %v", code, out)
	}
	c0, _ := totp.Code(sec, totp.Counter(e.clock()))
	if code, _ := b.csrfDo("POST", "/auth/totp/confirm", map[string]any{"code": c0}); code != 200 {
		t.Fatal("confirm")
	}
	if code, out := b.login("nida", "a much better password", nil); code != 401 || errCode(out) != "totp_required" {
		t.Fatalf("totp required: %d %v", code, out)
	}
	if code, _ := b.login("nida", "a much better password", map[string]any{"totp": c0}); code != 401 {
		t.Fatal("a code is used once")
	}
	e.advance(30 * time.Second)
	c1, _ := totp.Code(sec, totp.Counter(e.clock()))
	if code, out := b.login("nida", "a much better password", map[string]any{"totp": c1}); code != 200 || out["amr"] != "pwd+totp" {
		t.Fatalf("totp login: %d %v", code, out)
	}
	// lock after 5 failures
	x := e.browser(t)
	for i := 0; i < 5; i++ {
		x.login("nida", "not-the-password", nil)
	}
	if code, out := x.login("nida", "a much better password", map[string]any{"totp": c1}); code != 423 || errCode(out) != "locked" {
		t.Fatalf("locked: %d %v", code, out)
	}
	if !e.plat.has("gateway.auth locked") {
		t.Fatal("lock audited")
	}
	e.advance(16 * time.Minute)
	c2, _ := totp.Code(sec, totp.Counter(e.clock()))
	if code, _ := x.login("nida", "a much better password", map[string]any{"totp": c2}); code != 200 {
		t.Fatal("unlocked after the lock period")
	}
}

func TestMobileTokens(t *testing.T) {
	e := setup(t)
	_, _ = e.g.CreateLocal(context.Background(), "rider", "", []string{"clerk"}, "bike-secret-0001")
	m := &client{t: t, e: e, hc: &http.Client{Transport: e.srv.Client().Transport}}
	code, out := m.login("rider", "bike-secret-0001", map[string]any{"client": "mobile"})
	ref := toS(out["refresh_token"])
	if code != 200 || m.bear == "" || ref == "" || out["csrf_token"] != nil {
		t.Fatalf("mobile login: %d %v", code, out)
	}
	if code, _ := m.do("POST", "/api/demo/v1/items", map[string]any{}); code != 200 {
		t.Fatal("bearer needs no CSRF")
	}
	e.advance(16 * time.Minute)
	if code, _ := m.do("GET", "/auth/me", nil); code != 401 {
		t.Fatal("access token expired")
	}
	old := m.bear
	code, out = m.do("POST", "/auth/refresh", map[string]any{"refresh_token": ref})
	if code != 200 || toS(out["access_token"]) == "" || toS(out["refresh_token"]) == ref {
		t.Fatalf("refresh: %d %v", code, out)
	}
	m.bear = toS(out["access_token"])
	if code, _ := m.do("GET", "/auth/me", nil); code != 200 {
		t.Fatal("new access token")
	}
	m2 := &client{t: t, e: e, hc: &http.Client{Transport: e.srv.Client().Transport}, bear: old}
	if code, _ := m2.do("POST", "/auth/refresh", map[string]any{"refresh_token": ref}); code != 401 {
		t.Fatal("an old refresh token is refused")
	}
	if code, _ := m.do("POST", "/auth/refresh", map[string]any{"refresh_token": "guess"}); code != 401 {
		t.Fatal("a wrong refresh token")
	}
	if code, _ := m.do("GET", "/auth/me", nil); code != 401 {
		t.Fatal("a wrong refresh token ends the session")
	}
}

func TestAdmin(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, _ = e.g.CreateLocal(ctx, "root", "Admin", []string{AdminRole}, "admin-password-1")
	a := e.browser(t)
	a.login("root", "admin-password-1", nil)
	code, out := a.csrfDo("POST", "/admin/users", map[string]any{"id": "pim", "name": "Pim", "roles": []string{"clerk"}})
	temp := toS(out["temporary_password"])
	if code != 200 || temp == "" {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, _ := a.csrfDo("POST", "/admin/users", map[string]any{"id": "pim", "roles": []string{}}); code != 409 {
		t.Fatal("exists")
	}
	if code, _ := a.do("POST", "/admin/users", map[string]any{"id": "x1", "roles": []string{}}); code != 403 {
		t.Fatal("admin changes need the CSRF token")
	}
	p := e.browser(t)
	p.login("pim", temp, map[string]any{"new_password": "my own passphrase"})
	if code, _ := p.do("GET", "/admin/users", nil); code != 403 {
		t.Fatal("not an admin")
	}
	if !e.plat.has("gateway.auth refused:not_admin pim") {
		t.Fatalf("refusal audited: %v", e.plat.events)
	}
	if code, _ := p.do("GET", "/api/demo/v1/items/1", nil); code != 200 {
		t.Fatal("pim as clerk")
	}
	code, out = a.csrfDo("PUT", "/admin/users/pim", map[string]any{"roles": []string{"manager"}})
	if code != 200 || out["sessions_ended"].(float64) != 1 {
		t.Fatalf("roles: %d %v", code, out)
	}
	if code, _ := p.do("GET", "/auth/me", nil); code != 401 {
		t.Fatal("a role change ends the sessions")
	}
	p.login("pim", "my own passphrase", nil)
	if code, _ := p.csrfDo("DELETE", "/api/demo/v1/items/1", nil); code != 200 {
		t.Fatal("pim as manager")
	}
	if code, _ := a.csrfDo("PUT", "/admin/users/pim", map[string]any{"disabled": true}); code != 200 {
		t.Fatal("disable")
	}
	if code, out := p.login("pim", "my own passphrase", nil); code != 403 || errCode(out) != "account_disabled" {
		t.Fatalf("disabled: %d %v", code, out)
	}
	if code, _ := a.csrfDo("PUT", "/admin/users/root", map[string]any{"roles": []string{"clerk"}}); code != 409 {
		t.Fatal("no self-demotion")
	}
	if code, out := a.do("GET", "/admin/users", nil); code != 200 || len(out["users"].([]any)) != 2 {
		t.Fatalf("list: %d %v", code, out)
	}
	if code, _ := a.csrfDo("DELETE", "/admin/users/pim", nil); code != 200 {
		t.Fatal("delete")
	}
	if _, err := e.g.Store.Credential(ctx, "pim"); err != store.ErrNotFound {
		t.Fatal("credential gone")
	}
	if code, out := a.do("GET", "/admin/routes", nil); code != 200 || len(out["routes"].([]any)) != 5 {
		t.Fatalf("routes: %d", code)
	}
}

func TestOIDC(t *testing.T) {
	e := setup(t)
	b := e.browser(t)
	b.hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.Path, "/authorize") {
			q := req.URL.Query()
			q.Set("login_hint", "alice")
			req.URL.RawQuery = q.Encode()
		}
		if req.URL.Path == "/welcome" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := b.hc.Get(e.srv.URL + "/auth/oidc/corp/start?return_to=/welcome")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/welcome" {
		t.Fatalf("callback should land on /welcome: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	code, out := b.do("GET", "/auth/me", nil)
	id := OIDCUserID("corp", e.idp.Issuer, "alice")
	if code != 200 || out["user"] != id || out["amr"] != "oidc:corp" || out["name"] != "Test alice" {
		t.Fatalf("me: %d %v", code, out)
	}
	if code, _ := b.do("GET", "/api/demo/v1/items/9", nil); code != 200 {
		t.Fatal("auto-created clerk")
	}
	// a callback without the browser's state cookie
	other := e.browser(t)
	other.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, _ = other.hc.Get(e.srv.URL + "/auth/oidc/corp/start")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	state := loc.Query().Get("state")
	fresh := e.browser(t) // another browser
	code, out = fresh.do("GET", "/auth/oidc/corp/callback?code=x&state="+state, nil)
	if code != 400 || errCode(out) != "bad_state" {
		t.Fatalf("state not bound: %d %v", code, out)
	}
	if code, _ := b.do("GET", "/auth/oidc/nope/start", nil); code != 404 {
		t.Fatal("unknown provider")
	}
	if code, out := b.do("GET", "/auth/oidc/corp/start?return_to=https://evil.example", nil); code != 200 && code != 302 {
		_ = out
	}
	if safeReturn("https://evil.example") != "/" || safeReturn("//evil") != "/" || safeReturn("/ok?x=1") != "/ok?x=1" {
		t.Fatal("return_to")
	}
}

func TestMatch(t *testing.T) {
	for _, c := range []struct {
		t, p string
		ok   bool
	}{
		{"/v1/items/{id}", "/v1/items/7", true}, {"/v1/items/{id}", "/v1/items/", false}, {"/v1/items/{id}", "/v1/items/7/x", false},
		{"/v1/files/{p...}", "/v1/files/a/b/c", true}, {"/v1/hello", "/v1/hello", true}, {"/v1/hello", "/v1/hellO", false},
	} {
		if match(c.t, c.p) != c.ok {
			t.Errorf("%s %s", c.t, c.p)
		}
	}
	for p, ok := range map[string]bool{"/a/b": true, "/a/../b": false, "/a//b": false, "/a/./b": false, "/a\\b": false} {
		if cleanPath(p) != ok {
			t.Errorf("clean %s", p)
		}
	}
}
