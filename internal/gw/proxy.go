package gw

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

// RefreshRoutes asks core for the exposed routes now.
func (g *Gateway) RefreshRoutes(ctx context.Context) error {
	rs, ver, err := g.Plat.Routes(ctx)
	if err != nil {
		return err
	}
	g.rmu.Lock()
	g.routes, g.routesVer, g.routesAt = rs, ver, g.Now()
	g.rmu.Unlock()
	return nil
}

// WatchRoutes keeps the routes fresh; a failed refresh keeps the last ones.
func (g *Gateway) WatchRoutes(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := g.RefreshRoutes(cctx)
			cancel()
			if err != nil && !failing {
				g.Logf("heain-gateway: routes from core: %v (keeping the last ones)", err)
			}
			failing = err != nil
		}
	}
}

// RoutesView is the routes as last seen.
func (g *Gateway) RoutesView() map[string]any {
	g.rmu.RLock()
	defer g.rmu.RUnlock()
	rs := g.routes
	if rs == nil {
		rs = []heain.GatewayRoute{}
	}
	return map[string]any{"config_version": g.routesVer, "at": g.routesAt, "routes": rs}
}

// match reports whether path fits template ("{x}" one segment, "{x...}"
// the rest).
func match(template, path string) bool {
	ts := strings.Split(strings.Trim(template, "/"), "/")
	ps := strings.Split(strings.Trim(path, "/"), "/")
	for i, t := range ts {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "...}") {
			return len(ps) >= i
		}
		if i >= len(ps) {
			return false
		}
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			if ps[i] == "" {
				return false
			}
			continue
		}
		if t != ps[i] {
			return false
		}
	}
	return len(ts) == len(ps)
}

// find returns the route of app for method and path.
func (g *Gateway) find(app, method, path string) (heain.GatewayRoute, bool) {
	g.rmu.RLock()
	defer g.rmu.RUnlock()
	var best heain.GatewayRoute
	found, bestScore := false, -1
	for _, r := range g.routes {
		if r.App != app || r.Method != method || !match(r.Path, path) {
			continue
		}
		// prefer the most literal template
		score := strings.Count(r.Path, "/") - strings.Count(r.Path, "{")
		if score > bestScore {
			best, found, bestScore = r, true, score
		}
	}
	return best, found
}

func cleanPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.ContainsAny(p, "\\\x00") {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}

var passReq = []string{"Content-Type", "Accept", "Accept-Language", "If-None-Match", "If-Modified-Since", "Range"}
var passResp = []string{"Content-Type", "Content-Length", "Content-Disposition", "Content-Range", "Accept-Ranges", "Cache-Control",
	"ETag", "Last-Modified", "Retry-After", "X-Heain-Trace"}

// proxy: <METHOD> /api/{app}/<path> -> the app instance serving the route.
func (g *Gateway) proxy(w http.ResponseWriter, r *http.Request) {
	app := r.PathValue("app")
	path := "/" + r.PathValue("rest")
	if !cleanPath(path) || app == "" {
		fail(w, http.StatusBadRequest, "bad_path", "malformed path")
		return
	}
	rt, ok := g.find(app, r.Method, path)
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such route")
		return
	}
	addr := g.clientAddr(r)
	trace := heain.NewID()
	ctx := heain.WithTrace(r.Context(), trace, "")
	d := map[string]any{"app": app, "method": r.Method, "route": rt.Path, "path": path, "client_addr": addr}
	auditOut := func(outcome string) { g.audit(ctx, "gateway.proxy", outcome, d) }

	var p *principal
	if rt.Auth != "anonymous" {
		var ok bool
		if p, ok = g.session(w, r, true); !ok {
			auditOut("refused:unauthenticated")
			return
		}
		d["user"], d["session"] = p.S.User, p.S.ID
		if len(rt.Roles) > 0 && !hasAnyRole(p.S.Roles, rt.Roles) {
			auditOut("refused:role")
			fail(w, http.StatusForbidden, "forbidden", "this route needs one of the roles "+strings.Join(rt.Roles, ", "))
			return
		}
	}
	rate := rt.RatePerMin
	if rate == 0 {
		rate = g.Cfg.DefaultRate
	}
	who := "addr:" + addr
	if p != nil {
		who = "user:" + p.S.User
	}
	if ok, wait := g.limit.Allow(rt.App+" "+rt.Method+" "+rt.Path+"|"+who, rate, g.Now()); !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		auditOut("refused:rate_limited")
		fail(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("at most %d requests a minute on this route", rate))
		return
	}
	if rt.Status != "ok" || len(rt.Instances) == 0 {
		auditOut("error:unavailable")
		fail(w, http.StatusServiceUnavailable, "unavailable", "no live instance serves this route now")
		return
	}
	g.rmu.Lock()
	k := rt.App + " " + rt.Method + " " + rt.Path
	n := g.rr[k]
	g.rr[k] = n + 1
	g.rmu.Unlock()
	inst := rt.Instances[n%len(rt.Instances)]
	d["instance"] = inst.InstanceID

	cl, err := g.Plat.Client(rt.App, inst.InstanceID)
	if err != nil {
		auditOut("error:client")
		fail(w, http.StatusBadGateway, "bad_gateway", "cannot reach the app")
		return
	}
	uctx, cancel := context.WithTimeout(ctx, g.Cfg.UpstreamTO)
	defer cancel()
	target := strings.TrimSuffix(inst.EndpointBase, "/") + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	var body io.Reader
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		body = http.MaxBytesReader(w, r.Body, g.Cfg.MaxBody)
	}
	req, err := http.NewRequestWithContext(uctx, r.Method, target, body)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	req.ContentLength = r.ContentLength
	for _, h := range passReq {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set(heain.HeaderTrace, trace)
	if rt.Lane != "" {
		req.Header.Set(heain.HeaderLane, rt.Lane)
	}
	if p != nil {
		a, err := g.Plat.Sign(heain.UserAssertion{Audience: rt.App, Method: r.Method, Path: path, Trace: trace, Subject: p.S.User,
			Name: p.S.Name, Roles: p.S.Roles, AuthMethod: p.S.AMR, Session: p.S.ID})
		if err != nil {
			auditOut("error:sign")
			fail(w, http.StatusInternalServerError, "internal", "cannot sign the user assertion")
			return
		}
		req.Header.Set(heain.HeaderUser, a)
	}
	resp, err := cl.Do(req)
	if err != nil {
		auditOut("error:upstream")
		if uctx.Err() != nil {
			fail(w, http.StatusGatewayTimeout, "timeout", "the app did not answer in time")
			return
		}
		fail(w, http.StatusBadGateway, "bad_gateway", "the app could not be reached")
		return
	}
	defer resp.Body.Close()
	for _, h := range passResp {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	d["status"] = resp.StatusCode
	outcome := "ok"
	if resp.StatusCode >= 400 {
		outcome = fmt.Sprintf("error:%d", resp.StatusCode)
	}
	auditOut(outcome)
}
