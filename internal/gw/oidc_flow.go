package gw

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/heainframework/heain-gateway/internal/secret"
)

type oidcPending struct {
	Provider, Nonce, Verifier, ReturnTo, Kind string
	Exp                                       time.Time
}

const oidcCookie = "heain_oidc"

// safeReturn accepts only a path on this gateway.
func safeReturn(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n") {
		return "/"
	}
	return s
}

// GET /auth/oidc/{p}/start[?return_to=/path]: to the provider's sign-in.
func (g *Gateway) oidcStart(w http.ResponseWriter, r *http.Request) {
	p, ok := g.Providers[r.PathValue("p")]
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such identity provider")
		return
	}
	if ok, _ := g.limit.Allow("oidc-addr|"+g.clientAddr(r), g.Cfg.LoginRate, g.Now()); !ok {
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many sign-in attempts from this address")
		return
	}
	state, nonce, verifier := secret.Token(24), secret.Token(24), secret.Token(48)
	g.pmu.Lock()
	if len(g.pending) > 100000 {
		g.pmu.Unlock()
		fail(w, http.StatusServiceUnavailable, "busy", "too many sign-ins in progress")
		return
	}
	g.pending[state] = oidcPending{Provider: p.Name, Nonce: nonce, Verifier: verifier, ReturnTo: safeReturn(r.URL.Query().Get("return_to")),
		Kind: "web", Exp: g.Now().Add(10 * time.Minute)}
	g.pmu.Unlock()
	// the state is bound to this browser: the callback must come with it
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: state, Path: "/auth/oidc/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, p.AuthURL(state, nonce, verifier), http.StatusFound)
}

// GET /auth/oidc/{p}/callback?code&state: back from the provider.
func (g *Gateway) oidcCallback(w http.ResponseWriter, r *http.Request) {
	p, ok := g.Providers[r.PathValue("p")]
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such identity provider")
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	c, err := r.Cookie(oidcCookie)
	g.pmu.Lock()
	pend, found := g.pending[state]
	delete(g.pending, state)
	g.pmu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/auth/oidc/", MaxAge: -1, HttpOnly: true, Secure: true})
	if err != nil || state == "" || c.Value != state || !found || pend.Provider != p.Name || g.Now().After(pend.Exp) {
		g.authAudit(r, "refused:oidc_state", map[string]any{"provider": p.Name})
		fail(w, http.StatusBadRequest, "bad_state", "this sign-in was not started here, or took too long; start again")
		return
	}
	if e := q.Get("error"); e != "" {
		g.authAudit(r, "refused:oidc_provider", map[string]any{"provider": p.Name, "error": e})
		fail(w, http.StatusUnauthorized, "provider_refused", "the identity provider refused: "+e)
		return
	}
	claims, err := p.Exchange(r.Context(), q.Get("code"), pend.Verifier, pend.Nonce)
	if err != nil {
		g.authAudit(r, "refused:oidc_token", map[string]any{"provider": p.Name, "reason": err.Error()})
		fail(w, http.StatusUnauthorized, "invalid_token", "the identity provider's answer did not verify")
		return
	}
	id := OIDCUserID(p.Name, p.Issuer, claims.Subject)
	ctx := r.Context()
	acc, err := g.Dir.Get(ctx, id)
	if errors.Is(err, ErrNoAccount) {
		if !p.AutoCreate {
			g.authAudit(r, "refused:no_account", map[string]any{"provider": p.Name, "user": id})
			fail(w, http.StatusForbidden, "no_account", "no account for this identity; ask an admin (account id "+id+")")
			return
		}
		name := claims.Name
		if name == "" {
			name = claims.Email
		}
		acc = Account{ID: id, Name: name, Roles: append([]string(nil), p.DefaultRoles...), Source: "oidc:" + p.Name}
		if err := g.Dir.Put(ctx, acc); err != nil {
			fail(w, http.StatusServiceUnavailable, "unavailable", "account directory: "+err.Error())
			return
		}
		g.authAudit(r, "account_created", map[string]any{"provider": p.Name, "user": id, "roles": acc.Roles})
	} else if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "account directory: "+err.Error())
		return
	}
	if acc.Disabled {
		g.authAudit(r, "refused:account_disabled", map[string]any{"user": id})
		fail(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	}
	now := g.Now()
	tok := secret.Token(32)
	ss := sessionFor(acc, "oidc:"+p.Name, "web", now, g.Cfg.SessionTTL, g.clientAddr(r))
	ss.Hash, ss.CSRF = secret.SHA256(tok), secret.Token(24)
	if err := g.Store.CreateSession(ss); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	g.setSessionCookies(w, tok, ss)
	g.authAudit(r, "ok", map[string]any{"user": id, "amr": ss.AMR, "kind": "web", "session": ss.ID})
	http.Redirect(w, r, pend.ReturnTo, http.StatusFound)
}
