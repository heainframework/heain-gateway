package gw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/heainframework/heain-gateway/internal/secret"
	"github.com/heainframework/heain-gateway/internal/store"
	"github.com/heainframework/heain-gateway/internal/totp"
)

// UserRe is a built-in account name.
var UserRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

// dummyHash makes a login for an unknown account take as long as a real one.
var dummyHash, _ = secret.Hash("heain-gateway-no-such-user")

type loginReq struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	TOTP        string `json:"totp,omitempty"`
	NewPassword string `json:"new_password,omitempty"`
	Client      string `json:"client,omitempty"` // web (default) | mobile
}

func (g *Gateway) authAudit(r *http.Request, outcome string, d map[string]any) {
	d["client_addr"] = g.clientAddr(r)
	g.audit(r.Context(), "gateway.auth", outcome, d)
}

func (g *Gateway) login(w http.ResponseWriter, r *http.Request) {
	var q loginReq
	if !decode(w, r, &q) {
		return
	}
	kind := q.Client
	if kind == "" {
		kind = "web"
	}
	if kind != "web" && kind != "mobile" {
		fail(w, http.StatusBadRequest, "bad_request", `client must be "web" or "mobile"`)
		return
	}
	now := g.Now()
	addr := g.clientAddr(r)
	if ok, wait := g.limit.Allow("login-addr|"+addr, g.Cfg.LoginRate, now); !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		g.authAudit(r, "refused:rate_limited", map[string]any{"user": q.Username})
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many sign-in attempts from this address")
		return
	}
	user := strings.ToLower(strings.TrimSpace(q.Username))
	bad := func(reason string) {
		g.authAudit(r, "refused:"+reason, map[string]any{"user": user})
		fail(w, http.StatusUnauthorized, "invalid_credentials", "wrong user name, password or code")
	}
	if !UserRe.MatchString(user) {
		secret.Verify(q.Password, dummyHash)
		bad("unknown_user")
		return
	}
	ctx := r.Context()
	c, err := g.Store.Credential(ctx, user)
	if errors.Is(err, store.ErrNotFound) {
		secret.Verify(q.Password, dummyHash)
		bad("unknown_user")
		return
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "credential store: "+err.Error())
		return
	}
	if now.Before(c.LockedUntil) {
		w.Header().Set("Retry-After", fmt.Sprint(int(c.LockedUntil.Sub(now).Seconds())+1))
		g.authAudit(r, "refused:locked", map[string]any{"user": user})
		fail(w, http.StatusLocked, "locked", "this account is locked after failed sign-ins; try later")
		return
	}
	failed := func(reason string) {
		c.Failures++
		if c.Failures >= g.Cfg.LockAfter {
			c.Failures, c.LockedUntil = 0, now.Add(g.Cfg.LockFor)
			g.authAudit(r, "locked", map[string]any{"user": user, "until": c.LockedUntil})
		}
		_ = g.Store.PutCredential(ctx, c)
		bad(reason)
	}
	if !secret.Verify(q.Password, c.PasswordH) {
		failed("wrong_password")
		return
	}
	amr := "pwd"
	if c.TOTPOn {
		if q.TOTP == "" {
			fail(w, http.StatusUnauthorized, "totp_required", "this account needs its authenticator code (totp)")
			return
		}
		n, ok := totp.Verify(c.TOTPSecret, q.TOTP, now)
		if !ok || n <= c.TOTPLast {
			failed("wrong_totp")
			return
		}
		c.TOTPLast, amr = n, "pwd+totp"
	}
	acc, err := g.Dir.Get(ctx, user)
	if errors.Is(err, ErrNoAccount) || (err == nil && acc.Disabled) {
		g.authAudit(r, "refused:account_disabled", map[string]any{"user": user})
		fail(w, http.StatusForbidden, "account_disabled", "this account is disabled or has no account record")
		return
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "account directory: "+err.Error())
		return
	}
	if c.MustChange {
		if q.NewPassword == "" {
			_ = g.Store.PutCredential(ctx, c) // keeps the TOTP counter
			fail(w, http.StatusForbidden, "password_change_required", "set a new password: send new_password with this sign-in")
			return
		}
		if err := secret.CheckPolicy(q.NewPassword, user); err != nil || q.NewPassword == q.Password {
			msg := "the new password must differ from the old one"
			if err != nil {
				msg = err.Error()
			}
			fail(w, http.StatusBadRequest, "weak_password", msg)
			return
		}
		h, err := secret.Hash(q.NewPassword)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		c.PasswordH, c.MustChange, c.Changed = h, false, now
		g.authAudit(r, "password_changed", map[string]any{"user": user})
	}
	c.Failures, c.LockedUntil = 0, time.Time{}
	if err := g.Store.PutCredential(ctx, c); err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "credential store: "+err.Error())
		return
	}
	ss := g.newSession(w, r, acc, amr, kind)
	g.authAudit(r, "ok", map[string]any{"user": user, "amr": amr, "kind": kind, "session": ss.ID})
}

func (g *Gateway) refresh(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &q) {
		return
	}
	tok, _ := g.tokenOf(r)
	now := g.Now()
	refused := func() {
		fail(w, http.StatusUnauthorized, "unauthenticated", "the refresh token is not valid; sign in again")
	}
	if tok == "" || q.RefreshToken == "" {
		refused()
		return
	}
	old := secret.SHA256(tok)
	ss, err := g.Store.Session(old)
	if err != nil || ss.Kind != "mobile" || now.After(ss.Expires) || ss.RefreshH != secret.SHA256(q.RefreshToken) {
		if err == nil && ss.RefreshH != secret.SHA256(q.RefreshToken) {
			// a refresh token used twice, or guessed: end the session
			_ = g.Store.DeleteSession(old)
			g.authAudit(r, "refused:refresh_reuse", map[string]any{"user": ss.User, "session": ss.ID})
		}
		refused()
		return
	}
	acc, err := g.Dir.Get(r.Context(), ss.User)
	if err != nil || acc.Disabled {
		_ = g.Store.DeleteSession(old)
		refused()
		return
	}
	nt, nr := secret.Token(32), secret.Token(32)
	ss.Hash, ss.RefreshH, ss.AccessExp, ss.LastSeen, ss.Roles, ss.Name = secret.SHA256(nt), secret.SHA256(nr), now.Add(g.Cfg.AccessTTL), now, acc.Roles, acc.Name
	if err := g.Store.Replace(old, ss); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": nt, "refresh_token": nr, "token_type": "Bearer",
		"expires_in": int(g.Cfg.AccessTTL.Seconds()), "expires": ss.Expires, "roles": acc.Roles})
}

func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	p, ok := g.session(w, r, true)
	if !ok {
		return
	}
	_ = g.Store.DeleteSession(p.S.Hash)
	if !p.Bearer {
		http.SetCookie(w, &http.Cookie{Name: g.Cfg.CookieName, Value: "", Path: "/", HttpOnly: true, Secure: true, MaxAge: -1, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "heain_csrf", Value: "", Path: "/", Secure: true, MaxAge: -1, SameSite: http.SameSiteLaxMode})
	}
	g.authAudit(r, "logout", map[string]any{"user": p.S.User, "session": p.S.ID})
	writeJSON(w, http.StatusOK, map[string]any{"status": "signed_out"})
}

func (g *Gateway) me(w http.ResponseWriter, r *http.Request) {
	p, ok := g.session(w, r, true)
	if !ok {
		return
	}
	out := map[string]any{"user": p.S.User, "name": p.S.Name, "roles": p.S.Roles, "amr": p.S.AMR, "kind": p.S.Kind,
		"session": p.S.ID, "expires": p.S.Expires}
	if c, err := g.Store.Credential(r.Context(), p.S.User); err == nil {
		out["totp"] = c.TOTPOn
	}
	writeJSON(w, http.StatusOK, out)
}

// localCred is the signed-in person's built-in credential.
func (g *Gateway) localCred(w http.ResponseWriter, ctx context.Context, user string) (store.Credential, bool) {
	c, err := g.Store.Credential(ctx, user)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusConflict, "not_local", "this account signs in through its identity provider")
		return c, false
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return c, false
	}
	return c, true
}

func (g *Gateway) changePassword(w http.ResponseWriter, r *http.Request) {
	p, ok := g.session(w, r, true)
	if !ok {
		return
	}
	var q struct {
		Password    string `json:"password"`
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, &q) {
		return
	}
	c, ok := g.localCred(w, r.Context(), p.S.User)
	if !ok {
		return
	}
	if !secret.Verify(q.Password, c.PasswordH) {
		g.authAudit(r, "refused:wrong_password", map[string]any{"user": p.S.User, "op": "password_change"})
		fail(w, http.StatusForbidden, "invalid_credentials", "the current password is wrong")
		return
	}
	if err := secret.CheckPolicy(q.NewPassword, p.S.User); err != nil {
		fail(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	h, _ := secret.Hash(q.NewPassword)
	c.PasswordH, c.MustChange, c.Changed = h, false, g.Now()
	if err := g.Store.PutCredential(r.Context(), c); err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	// every other session of the person ends
	n, _ := g.Store.RevokeUser(p.S.User)
	_ = g.Store.PutSession(p.S)
	g.authAudit(r, "password_changed", map[string]any{"user": p.S.User, "other_sessions_ended": n - 1})
	writeJSON(w, http.StatusOK, map[string]any{"status": "changed"})
}

func (g *Gateway) totpSetup(w http.ResponseWriter, r *http.Request) {
	p, ok := g.session(w, r, true)
	if !ok {
		return
	}
	var q struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &q) {
		return
	}
	c, ok := g.localCred(w, r.Context(), p.S.User)
	if !ok {
		return
	}
	if !secret.Verify(q.Password, c.PasswordH) {
		fail(w, http.StatusForbidden, "invalid_credentials", "the password is wrong")
		return
	}
	if c.TOTPOn {
		fail(w, http.StatusConflict, "totp_on", "an authenticator is already set up; an admin can reset it")
		return
	}
	c.TOTPSecret = totp.NewSecret()
	if err := g.Store.PutCredential(r.Context(), c); err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": c.TOTPSecret, "otpauth_uri": totp.URI(g.Cfg.Issuer, p.S.User, c.TOTPSecret),
		"next": "POST /auth/totp/confirm {code}"})
}

func (g *Gateway) totpConfirm(w http.ResponseWriter, r *http.Request) {
	p, ok := g.session(w, r, true)
	if !ok {
		return
	}
	var q struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &q) {
		return
	}
	c, ok := g.localCred(w, r.Context(), p.S.User)
	if !ok {
		return
	}
	if c.TOTPOn || c.TOTPSecret == "" {
		fail(w, http.StatusConflict, "no_setup", "start with POST /auth/totp/setup")
		return
	}
	n, valid := totp.Verify(c.TOTPSecret, q.Code, g.Now())
	if !valid {
		fail(w, http.StatusBadRequest, "wrong_code", "the code does not match")
		return
	}
	c.TOTPOn, c.TOTPLast = true, n
	if err := g.Store.PutCredential(r.Context(), c); err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	g.authAudit(r, "totp_enabled", map[string]any{"user": p.S.User})
	writeJSON(w, http.StatusOK, map[string]any{"status": "totp_on"})
}

func (g *Gateway) providers(w http.ResponseWriter, r *http.Request) {
	names := []string{}
	for n := range g.Providers {
		names = append(names, n)
	}
	writeJSON(w, http.StatusOK, map[string]any{"local": true, "oidc": names})
}
