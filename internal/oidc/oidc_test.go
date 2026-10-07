package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heainframework/heain-gateway/internal/oidc/fakeidp"
)

func TestFlow(t *testing.T) {
	idp := fakeidp.New("gw-client", "s3cret")
	srv := httptest.NewServer(idp)
	defer srv.Close()
	idp.Issuer = srv.URL
	os.Setenv("TEST_OIDC_SECRET", "s3cret")
	ctx := context.Background()
	p, err := Discover(ctx, Config{Name: "test", Issuer: srv.URL, ClientID: "gw-client", ClientSecretEnv: "TEST_OIDC_SECRET", RedirectURL: "https://gw.example/auth/oidc/test/callback"})
	if err != nil {
		t.Fatal(err)
	}
	login := func(verifier, nonce string) (string, string) {
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := c.Get(p.AuthURL("st-1", nonce, verifier) + "&login_hint=alice")
		if err != nil || resp.StatusCode != 302 {
			t.Fatalf("authorize: %v %v", err, resp)
		}
		u, _ := url.Parse(resp.Header.Get("Location"))
		return u.Query().Get("code"), u.Query().Get("state")
	}
	code, state := login("verifier-0123456789-0123456789-0123456789", "n-1")
	if state != "st-1" {
		t.Fatal("state")
	}
	c, err := p.Exchange(ctx, code, "verifier-0123456789-0123456789-0123456789", "n-1")
	if err != nil || c.Subject != "alice" || c.Email != "alice@example.test" {
		t.Fatalf("exchange: %+v %v", c, err)
	}
	if _, err := p.Exchange(ctx, code, "verifier-0123456789-0123456789-0123456789", "n-1"); err == nil {
		t.Fatal("a code is used once")
	}
	code, _ = login("verifier-A-0123456789-0123456789-01234567", "n-2")
	if _, err := p.Exchange(ctx, code, "verifier-B-0123456789-0123456789-01234567", "n-2"); err == nil {
		t.Fatal("wrong PKCE verifier")
	}
	code, _ = login("v-0123456789-0123456789-0123456789-0123456", "n-3")
	if _, err := p.Exchange(ctx, code, "v-0123456789-0123456789-0123456789-0123456", "other-nonce"); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("nonce: %v", err)
	}
	for name, f := range map[string]func(map[string]any){
		"audience": func(m map[string]any) { m["aud"] = "someone-else" },
		"issuer":   func(m map[string]any) { m["iss"] = "https://evil.example" },
		"expired":  func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() },
	} {
		idp.Tamper = f
		code, _ = login("v-0123456789-0123456789-0123456789-0123456", "n-4")
		if _, err := p.Exchange(ctx, code, "v-0123456789-0123456789-0123456789-0123456", "n-4"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a token whose signature was altered
	parts := strings.Split("a.b.c", ".")
	if _, err := p.Verify(ctx, strings.Join(parts, "."), "n", time.Now()); err == nil {
		t.Fatal("garbage token")
	}
	if (Config{Name: "Bad Name", Issuer: "https://x", ClientID: "c", RedirectURL: "r"}).Check() == nil {
		t.Fatal("name check")
	}
	if Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatal("RFC 7636 S256 example")
	}
}
