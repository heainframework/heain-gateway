// Package oidc is the OpenID Connect relying party heain-gateway needs: the
// authorization code flow with PKCE (S256), a state and a nonce, the code
// exchanged at the provider's token endpoint, and the ID token verified
// against the provider's published keys (RS256 or ES256): issuer, audience,
// expiry, nonce. Standard library only.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config is one provider (from the -oidc-config file).
type Config struct {
	Name            string   `json:"name"`   // [a-z0-9-]: the path /auth/oidc/{name}/...
	Issuer          string   `json:"issuer"` // e.g. https://accounts.google.com
	ClientID        string   `json:"client_id"`
	ClientSecretEnv string   `json:"client_secret_env,omitempty"` // the secret is read from this variable, never the file
	RedirectURL     string   `json:"redirect_url"`                // https://<gateway>/auth/oidc/{name}/callback
	Scopes          []string `json:"scopes,omitempty"`            // default openid profile email
	AutoCreate      bool     `json:"auto_create,omitempty"`       // first login creates the account
	DefaultRoles    []string `json:"default_roles,omitempty"`     // roles of an auto-created account
	// HTTP (tests) replaces the client used to reach the provider.
	HTTP *http.Client `json:"-"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// Check validates c.
func (c Config) Check() error {
	switch {
	case !nameRe.MatchString(c.Name):
		return fmt.Errorf("oidc: name %q must match %s", c.Name, nameRe)
	case !strings.HasPrefix(c.Issuer, "https://") && !strings.HasPrefix(c.Issuer, "http://127.0.0.1"):
		return fmt.Errorf("oidc %s: issuer must be https", c.Name)
	case c.ClientID == "":
		return fmt.Errorf("oidc %s: client_id is required", c.Name)
	case c.RedirectURL == "":
		return fmt.Errorf("oidc %s: redirect_url is required", c.Name)
	}
	return nil
}

// Provider is a discovered provider.
type Provider struct {
	Config
	AuthEndpoint  string
	TokenEndpoint string
	JWKSURI       string
	secret        string

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	keysAt  time.Time
	refetch time.Time
}

type discovery struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

func (p *Provider) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Discover reads the provider's /.well-known/openid-configuration.
func Discover(ctx context.Context, c Config) (*Provider, error) {
	if err := c.Check(); err != nil {
		return nil, err
	}
	p := &Provider{Config: c}
	if c.ClientSecretEnv != "" {
		p.secret = os.Getenv(c.ClientSecretEnv)
		if p.secret == "" {
			return nil, fmt.Errorf("oidc %s: %s is empty", c.Name, c.ClientSecretEnv)
		}
	}
	var d discovery
	if err := p.getJSON(ctx, strings.TrimSuffix(c.Issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return nil, fmt.Errorf("oidc %s: discovery: %w", c.Name, err)
	}
	if strings.TrimSuffix(d.Issuer, "/") != strings.TrimSuffix(c.Issuer, "/") {
		return nil, fmt.Errorf("oidc %s: discovery names issuer %q", c.Name, d.Issuer)
	}
	if d.AuthEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("oidc %s: discovery lacks an endpoint", c.Name)
	}
	p.AuthEndpoint, p.TokenEndpoint, p.JWKSURI = d.AuthEndpoint, d.TokenEndpoint, d.JWKSURI
	return p, nil
}

func (p *Provider) getJSON(ctx context.Context, u string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := p.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", u, resp.StatusCode)
	}
	return json.Unmarshal(b, out)
}

// Challenge is the S256 PKCE challenge of verifier.
func Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// AuthURL is where the browser goes to sign in.
func (p *Provider) AuthURL(state, nonce, verifier string) string {
	sc := p.Scopes
	if len(sc) == 0 {
		sc = []string{"openid", "profile", "email"}
	}
	v := url.Values{"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {p.RedirectURL},
		"scope": {strings.Join(sc, " ")}, "state": {state}, "nonce": {nonce},
		"code_challenge": {Challenge(verifier)}, "code_challenge_method": {"S256"}}
	sep := "?"
	if strings.Contains(p.AuthEndpoint, "?") {
		sep = "&"
	}
	return p.AuthEndpoint + sep + v.Encode()
}

// Claims are the ID token claims heain-gateway uses.
type Claims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      any    `json:"aud"`
	Expires       int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
	Nonce         string `json:"nonce"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	AZP           string `json:"azp"`
}

// Exchange swaps the code for tokens and returns the verified ID token's claims.
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (Claims, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.RedirectURL},
		"client_id": {p.ClientID}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.secret != "" {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.secret))
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return Claims{}, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Claims{}, fmt.Errorf("token endpoint answered %d", resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(b, &tok); err != nil || tok.IDToken == "" {
		return Claims{}, errors.New("token endpoint returned no id_token")
	}
	return p.Verify(ctx, tok.IDToken, nonce, time.Now())
}

// Verify checks an ID token: signature (RS256 / ES256, from the JWKS),
// issuer, audience, expiry, nonce.
func (p *Provider) Verify(ctx context.Context, idToken, nonce string, now time.Time) (Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("id_token is not a JWS")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return Claims{}, errors.New("id_token is not base64url")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return Claims{}, errors.New("id_token header")
	}
	key, err := p.key(ctx, hdr.Kid)
	if err != nil {
		return Claims{}, err
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr.Alg {
	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) != nil {
			return Claims{}, errors.New("id_token signature does not verify")
		}
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 || !ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return Claims{}, errors.New("id_token signature does not verify")
		}
	default:
		return Claims{}, fmt.Errorf("id_token algorithm %q is not accepted", hdr.Alg)
	}
	var c Claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return Claims{}, errors.New("id_token claims")
	}
	if strings.TrimSuffix(c.Issuer, "/") != strings.TrimSuffix(p.Issuer, "/") {
		return Claims{}, fmt.Errorf("id_token issuer %q", c.Issuer)
	}
	if !audHas(c.Audience, p.ClientID) {
		return Claims{}, errors.New("id_token is for another client")
	}
	if c.AZP != "" && c.AZP != p.ClientID {
		return Claims{}, errors.New("id_token azp is another client")
	}
	if c.Expires == 0 || now.After(time.Unix(c.Expires, 0).Add(time.Minute)) {
		return Claims{}, errors.New("id_token expired")
	}
	if c.IssuedAt != 0 && time.Unix(c.IssuedAt, 0).After(now.Add(5*time.Minute)) {
		return Claims{}, errors.New("id_token issued in the future")
	}
	if nonce == "" || c.Nonce != nonce {
		return Claims{}, errors.New("id_token nonce does not match")
	}
	if c.Subject == "" {
		return Claims{}, errors.New("id_token has no subject")
	}
	return c, nil
}

func audHas(aud any, id string) bool {
	switch a := aud.(type) {
	case string:
		return a == id
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == id {
				return true
			}
		}
	}
	return false
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// key finds kid in the JWKS, fetching it again (at most once a minute) when
// a kid is unknown -- providers rotate keys.
func (p *Provider) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[kid]; ok && time.Since(p.keysAt) < 24*time.Hour {
		return k, nil
	}
	if time.Now().Before(p.refetch) && p.keys != nil {
		if k, ok := p.keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("id_token key %q unknown", kid)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(ctx, p.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(n) < 256 {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !pk.Curve.IsOnCurve(pk.X, pk.Y) {
				continue
			}
			keys[k.Kid] = pk
		}
	}
	p.keys, p.keysAt, p.refetch = keys, time.Now(), time.Now().Add(time.Minute)
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("id_token key %q unknown", kid)
}

// LoadConfigs reads the -oidc-config file (a JSON list).
func LoadConfigs(path string) ([]Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cs []Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, c := range cs {
		if err := c.Check(); err != nil {
			return nil, err
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("oidc provider %q twice", c.Name)
		}
		seen[c.Name] = true
	}
	return cs, nil
}
