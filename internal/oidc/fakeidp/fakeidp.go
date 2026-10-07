// Package fakeidp is a minimal OpenID provider for tests (TEST ONLY): it
// signs in whoever login_hint names, without asking, and issues RS256 ID
// tokens. It checks the client, the redirect URI and the PKCE verifier.
package fakeidp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// IdP is the fake provider.
type IdP struct {
	Issuer   string // set before serving (the server's base URL)
	ClientID string
	Secret   string
	key      *rsa.PrivateKey
	mu       sync.Mutex
	codes    map[string]grant
	// Tamper, when set, changes the claims of the next token (tests).
	Tamper func(map[string]any)
}

type grant struct {
	sub, name, email, nonce, challenge, redirect string
}

// New makes a provider for client id/secret.
func New(clientID, secret string) *IdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &IdP{ClientID: clientID, Secret: secret, key: k, codes: map[string]grant{}}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (p *IdP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.Issuer, "authorization_endpoint": p.Issuer + "/authorize",
			"token_endpoint": p.Issuer + "/token", "jwks_uri": p.Issuer + "/jwks"})
	case "/jwks":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64(p.key.N.Bytes()), "e": b64(big.NewInt(int64(p.key.E)).Bytes())}}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != p.ClientID || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
			http.Error(w, "bad request", 400)
			return
		}
		sub := q.Get("login_hint")
		if sub == "" {
			sub = "user-1"
		}
		cb := make([]byte, 16)
		_, _ = rand.Read(cb)
		code := b64(cb)
		p.mu.Lock()
		p.codes[code] = grant{sub: sub, name: "Test " + sub, email: sub + "@example.test", nonce: q.Get("nonce"),
			challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		p.mu.Unlock()
		u, _ := url.Parse(q.Get("redirect_uri"))
		v := u.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	case "/token":
		_ = r.ParseForm()
		id, sec, ok := r.BasicAuth()
		if !ok || id != p.ClientID || sec != p.Secret {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		p.mu.Lock()
		g, found := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		tamper := p.Tamper
		p.Tamper = nil
		p.mu.Unlock()
		h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !found || b64(h[:]) != g.challenge || r.Form.Get("redirect_uri") != g.redirect {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		now := time.Now().Unix()
		claims := map[string]any{"iss": p.Issuer, "sub": g.sub, "aud": p.ClientID, "exp": now + 300, "iat": now, "nonce": g.nonce,
			"name": g.name, "email": g.email, "email_verified": true}
		if tamper != nil {
			tamper(claims)
		}
		hb, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
		cb, _ := json.Marshal(claims)
		in := b64(hb) + "." + b64(cb)
		d := sha256.Sum256([]byte(in))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, d[:])
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": in + "." + b64(sig), "access_token": "unused", "token_type": "Bearer"})
	default:
		http.NotFound(w, r)
	}
}
