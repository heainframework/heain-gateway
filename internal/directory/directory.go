// Package directory keeps people's accounts in heain-database (author
// decision 2026-10-07): account id "person:<id>", role "person", and in
// metadata_kv the name, the roles (comma-separated), the source (local or
// oidc:<provider>) and whether it is disabled. Credentials never go there.
package directory

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/heainframework/heain-gateway/internal/gw"
	"github.com/heainframework/heain-sdk/heain"
)

// Prefix marks the gateway's accounts in heain-database.
const Prefix = "person:"

// Caller makes the direct call (heain-sdk App.Call).
type Caller interface {
	Call(ctx context.Context, cs heain.CallSpec) (int, error)
}

// DB is the heain-database directory.
type DB struct{ App Caller }

type record struct {
	ID         string            `json:"id,omitempty"`
	Role       string            `json:"role"`
	MetadataKV map[string]string `json:"metadata_kv,omitempty"`
}

func toAccount(r record) gw.Account {
	a := gw.Account{ID: strings.TrimPrefix(r.ID, Prefix), Name: r.MetadataKV["name"], Source: r.MetadataKV["source"],
		Disabled: r.MetadataKV["disabled"] == "true", Roles: []string{}}
	for _, x := range strings.Split(r.MetadataKV["roles"], ",") {
		if x = strings.TrimSpace(x); x != "" {
			a.Roles = append(a.Roles, x)
		}
	}
	return a
}

func path(id string) string { return "/v1/accounts/" + url.PathEscape(Prefix+id) }

// Get reads an account.
func (d DB) Get(ctx context.Context, id string) (gw.Account, error) {
	var r record
	_, err := d.App.Call(ctx, heain.CallSpec{App: "heain-database", Capability: "db.account.read", Method: http.MethodGet, Path: path(id), Out: &r})
	var ce *heain.CallError
	if errors.As(err, &ce) && ce.Status == http.StatusNotFound {
		return gw.Account{}, gw.ErrNoAccount
	}
	if err != nil {
		return gw.Account{}, err
	}
	r.ID = Prefix + id
	return toAccount(r), nil
}

// Put writes an account.
func (d DB) Put(ctx context.Context, a gw.Account) error {
	roles := append([]string(nil), a.Roles...)
	sort.Strings(roles)
	kv := map[string]string{"name": a.Name, "roles": strings.Join(roles, ","), "source": a.Source}
	if a.Disabled {
		kv["disabled"] = "true"
	}
	_, err := d.App.Call(ctx, heain.CallSpec{App: "heain-database", Capability: "db.account.write", Method: http.MethodPut, Path: path(a.ID),
		Body: record{Role: "person", MetadataKV: kv}})
	return err
}

// Delete removes an account.
func (d DB) Delete(ctx context.Context, id string) error {
	_, err := d.App.Call(ctx, heain.CallSpec{App: "heain-database", Capability: "db.account.write", Method: http.MethodDelete, Path: path(id)})
	return err
}

// List lists the gateway's accounts.
func (d DB) List(ctx context.Context) ([]gw.Account, error) {
	var out struct {
		Accounts []record `json:"accounts"`
	}
	if _, err := d.App.Call(ctx, heain.CallSpec{App: "heain-database", Capability: "db.account.read", Method: http.MethodGet, Path: "/v1/accounts", Out: &out}); err != nil {
		return nil, err
	}
	l := []gw.Account{}
	for _, r := range out.Accounts {
		if strings.HasPrefix(r.ID, Prefix) {
			l = append(l, toAccount(r))
		}
	}
	return l, nil
}
