package gw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/heainframework/heain-gateway/internal/secret"
	"github.com/heainframework/heain-gateway/internal/store"
)

var roleRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func checkRoles(rs []string) error {
	for _, r := range rs {
		if !roleRe.MatchString(r) {
			return errors.New("bad role name " + r)
		}
	}
	return nil
}

// OIDCUserID is the account id of an OIDC subject.
func OIDCUserID(provider, issuer, subject string) string {
	h := sha256.Sum256([]byte(strings.TrimSuffix(issuer, "/") + "|" + subject))
	return provider + "." + hex.EncodeToString(h[:])[:20]
}

type adminHandler func(w http.ResponseWriter, r *http.Request, p *principal)

// admin requires a session with the gateway-admin role (and, for a web
// session, the CSRF token on changes).
func (g *Gateway) admin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := g.session(w, r, true)
		if !ok {
			return
		}
		if !hasAnyRole(p.S.Roles, []string{AdminRole}) {
			g.authAudit(r, "refused:not_admin", map[string]any{"user": p.S.User, "op": r.Method + " " + r.URL.Path})
			fail(w, http.StatusForbidden, "forbidden", "needs the "+AdminRole+" role")
			return
		}
		h(w, r, p)
	}
}

func (g *Gateway) adminAudit(r *http.Request, p *principal, op, target string, d map[string]any) {
	if d == nil {
		d = map[string]any{}
	}
	d["admin"], d["op"], d["target"] = p.S.User, op, target
	g.authAudit(r, "admin", d)
}

func (g *Gateway) adminList(w http.ResponseWriter, r *http.Request, p *principal) {
	l, err := g.Dir.List(r.Context())
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "account directory: "+err.Error())
		return
	}
	sort.Slice(l, func(i, j int) bool { return l[i].ID < l[j].ID })
	writeJSON(w, http.StatusOK, map[string]any{"users": l})
}

func (g *Gateway) adminGet(w http.ResponseWriter, r *http.Request, p *principal) {
	id := r.PathValue("id")
	a, err := g.Dir.Get(r.Context(), id)
	if errors.Is(err, ErrNoAccount) {
		fail(w, http.StatusNotFound, "not_found", "no such account")
		return
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	out := map[string]any{"account": a}
	if c, err := g.Store.Credential(r.Context(), id); err == nil {
		out["local"] = map[string]any{"totp": c.TOTPOn, "must_change": c.MustChange, "locked_until": c.LockedUntil}
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateLocal makes a built-in account: the record in the directory, the
// credential here. An empty password makes a temporary one (returned) that
// must be changed at the first sign-in.
func (g *Gateway) CreateLocal(ctx context.Context, id, name string, roles []string, password string) (string, error) {
	temp := ""
	mustChange := false
	if password == "" {
		temp = secret.Token(15)
		password, mustChange = temp, true
	} else if err := secret.CheckPolicy(password, id); err != nil {
		return "", err
	}
	h, err := secret.Hash(password)
	if err != nil {
		return "", err
	}
	now := g.Now()
	if err := g.Dir.Put(ctx, Account{ID: id, Name: name, Roles: roles, Source: "local"}); err != nil {
		return "", err
	}
	if err := g.Store.PutCredential(ctx, store.Credential{User: id, PasswordH: h, MustChange: mustChange, Created: now, Changed: now}); err != nil {
		return "", err
	}
	return temp, nil
}

func (g *Gateway) adminCreate(w http.ResponseWriter, r *http.Request, p *principal) {
	var q struct {
		ID       string   `json:"id,omitempty"`
		Name     string   `json:"name,omitempty"`
		Roles    []string `json:"roles"`
		Password string   `json:"password,omitempty"`
		OIDC     *struct {
			Provider string `json:"provider"`
			Subject  string `json:"subject"`
		} `json:"oidc,omitempty"`
	}
	if !decode(w, r, &q) {
		return
	}
	if err := checkRoles(q.Roles); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx := r.Context()
	if q.OIDC != nil {
		pr, ok := g.Providers[q.OIDC.Provider]
		if !ok || q.OIDC.Subject == "" || q.Password != "" {
			fail(w, http.StatusBadRequest, "bad_request", "oidc needs a configured provider and the subject, and takes no password")
			return
		}
		id := OIDCUserID(pr.Name, pr.Issuer, q.OIDC.Subject)
		if _, err := g.Dir.Get(ctx, id); err == nil {
			fail(w, http.StatusConflict, "exists", "the account exists")
			return
		}
		a := Account{ID: id, Name: q.Name, Roles: q.Roles, Source: "oidc:" + pr.Name}
		if err := g.Dir.Put(ctx, a); err != nil {
			fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
			return
		}
		g.adminAudit(r, p, "create", id, map[string]any{"roles": q.Roles, "source": a.Source})
		writeJSON(w, http.StatusOK, map[string]any{"account": a})
		return
	}
	id := strings.ToLower(q.ID)
	if !UserRe.MatchString(id) || strings.Contains(id, ".") && g.Providers[strings.SplitN(id, ".", 2)[0]] != nil {
		fail(w, http.StatusBadRequest, "bad_request", "id must match "+UserRe.String()+" and not look like an OIDC account")
		return
	}
	if _, err := g.Store.Credential(ctx, id); err == nil {
		fail(w, http.StatusConflict, "exists", "the account exists")
		return
	}
	if _, err := g.Dir.Get(ctx, id); err == nil {
		fail(w, http.StatusConflict, "exists", "the account exists in the directory")
		return
	}
	temp, err := g.CreateLocal(ctx, id, q.Name, q.Roles, q.Password)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	g.adminAudit(r, p, "create", id, map[string]any{"roles": q.Roles, "source": "local", "temporary_password": temp != ""})
	out := map[string]any{"account": Account{ID: id, Name: q.Name, Roles: q.Roles, Source: "local"}}
	if temp != "" {
		out["temporary_password"] = temp
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *Gateway) adminUpdate(w http.ResponseWriter, r *http.Request, p *principal) {
	var q struct {
		Name     *string   `json:"name,omitempty"`
		Roles    *[]string `json:"roles,omitempty"`
		Disabled *bool     `json:"disabled,omitempty"`
	}
	if !decode(w, r, &q) {
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	a, err := g.Dir.Get(ctx, id)
	if errors.Is(err, ErrNoAccount) {
		fail(w, http.StatusNotFound, "not_found", "no such account")
		return
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	if q.Roles != nil {
		if err := checkRoles(*q.Roles); err != nil {
			fail(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		if id == p.S.User && !hasAnyRole(*q.Roles, []string{AdminRole}) {
			fail(w, http.StatusConflict, "self", "an admin cannot remove their own admin role")
			return
		}
		a.Roles = *q.Roles
	}
	if q.Name != nil {
		a.Name = *q.Name
	}
	if q.Disabled != nil {
		if id == p.S.User && *q.Disabled {
			fail(w, http.StatusConflict, "self", "an admin cannot disable themselves")
			return
		}
		a.Disabled = *q.Disabled
	}
	if err := g.Dir.Put(ctx, a); err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	// roles and the disabled flag take effect now: the person's sessions end
	n := 0
	if q.Roles != nil || q.Disabled != nil {
		n, _ = g.Store.RevokeUser(id)
	}
	g.adminAudit(r, p, "update", id, map[string]any{"roles": a.Roles, "disabled": a.Disabled, "sessions_ended": n})
	writeJSON(w, http.StatusOK, map[string]any{"account": a, "sessions_ended": n})
}

func (g *Gateway) adminReset(w http.ResponseWriter, r *http.Request, p *principal) {
	var q struct {
		Password  string `json:"password,omitempty"`
		ResetTOTP bool   `json:"reset_totp,omitempty"`
		Unlock    bool   `json:"unlock,omitempty"`
	}
	if !decode(w, r, &q) {
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	c, ok := g.localCred(w, ctx, id)
	if !ok {
		return
	}
	out := map[string]any{}
	if q.Password != "" || (!q.ResetTOTP && !q.Unlock) {
		pw, temp := q.Password, ""
		if pw == "" {
			temp = secret.Token(15)
			pw = temp
		} else if err := secret.CheckPolicy(pw, id); err != nil {
			fail(w, http.StatusBadRequest, "weak_password", err.Error())
			return
		}
		h, _ := secret.Hash(pw)
		c.PasswordH, c.MustChange = h, true
		if temp != "" {
			out["temporary_password"] = temp
		}
	}
	if q.ResetTOTP {
		c.TOTPOn, c.TOTPSecret, c.TOTPLast = false, "", 0
	}
	c.Failures, c.LockedUntil = 0, time.Time{}
	if err := g.Store.PutCredential(ctx, c); err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	n, _ := g.Store.RevokeUser(id)
	g.adminAudit(r, p, "reset", id, map[string]any{"password": q.Password != "" || (!q.ResetTOTP && !q.Unlock), "totp": q.ResetTOTP, "sessions_ended": n})
	out["status"], out["sessions_ended"] = "reset", n
	writeJSON(w, http.StatusOK, out)
}

func (g *Gateway) adminDelete(w http.ResponseWriter, r *http.Request, p *principal) {
	id := r.PathValue("id")
	if id == p.S.User {
		fail(w, http.StatusConflict, "self", "an admin cannot remove themselves")
		return
	}
	ctx := r.Context()
	if _, err := g.Dir.Get(ctx, id); errors.Is(err, ErrNoAccount) {
		fail(w, http.StatusNotFound, "not_found", "no such account")
		return
	}
	n, _ := g.Store.RevokeUser(id)
	if _, err := g.Store.Credential(ctx, id); err == nil {
		if err := g.Store.DeleteCredential(ctx, id); err != nil {
			fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
			return
		}
	}
	if err := g.Dir.Delete(ctx, id); err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	g.adminAudit(r, p, "delete", id, map[string]any{"sessions_ended": n})
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "sessions_ended": n})
}

func (g *Gateway) adminRevoke(w http.ResponseWriter, r *http.Request, p *principal) {
	id := r.PathValue("id")
	n, err := g.Store.RevokeUser(id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	g.adminAudit(r, p, "revoke_sessions", id, map[string]any{"sessions_ended": n})
	writeJSON(w, http.StatusOK, map[string]any{"sessions_ended": n})
}

func (g *Gateway) adminRoutes(w http.ResponseWriter, r *http.Request, p *principal) {
	writeJSON(w, http.StatusOK, g.RoutesView())
}
