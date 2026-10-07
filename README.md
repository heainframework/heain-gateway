# heain-gateway

The way in for people — web and mobile — to the apps of a heain deployment (Step 4.6a, 2026-10-07). Inside a deployment, apps call each other with app certificates (mTLS). People cannot do that. heain-gateway signs people in, lets them reach only the app endpoints the deployment exposes, and tells each app, with a signed assertion, which person is calling.

Built on [heain-sdk](https://github.com/heainframework/heain-sdk) v1 (Step 4.6a-2), with heain-core's gateway support (Step 4.6a-1). It passes the heain conformance suite. Run it however you like: a plain process, a service unit, or a container (Docker is not required).

## Author decisions (2026-10-07)

1. **Login.**
   - Built-in accounts use a password plus TOTP.
   - The credentials are sealed here, under keys held in heain-core's KMS.
   - The account record (who the account is, its roles) lives in heain-database.
   - OIDC providers can be connected too.
2. **Public routes.** An app declares in its manifest which endpoints may be public (`endpoints[].public: true`). heain-core's `gateway.exposures` exposes them, and that is a policy change approved through P5.
3. **The person reaches the app as a signed assertion.** heain-sdk verifies it, and the app reads it with `heain.UserOf(ctx)`. The assertion is kept in the audit.
4. **Authorization is split.** The gateway checks the route's roles at the door. The app checks data-level rights itself.

## What it does

**Sign-in (`POST /auth/login {username, password, totp?, new_password?, client: web|mobile}`)**
- Passwords are hashed with PBKDF2-HMAC-SHA256 (600 000 iterations, Go standard library) and must be at least 10 characters.
- TOTP follows RFC 6238 and works with any authenticator app. A code is accepted only once.
- An account locks after 5 failed sign-ins, for 15 minutes.
- Sign-in attempts are rate-limited per address.
- A temporary password must be replaced at the first sign-in.
- Every sign-in and every refusal is audited in core (`gateway.auth`).

**Sessions**
- **Web:** an HttpOnly, Secure, SameSite=Lax cookie plus a CSRF token. The token is in the login answer and in the readable `heain_csrf` cookie, and every unsafe method must send it as `X-CSRF-Token`.
  - A web session ends after `-idle-ttl` (30 minutes) without a request, and after `-session-ttl` (12 hours) in any case.
- **Mobile:** an access token (`-access-ttl`, 15 minutes) and a refresh token. `POST /auth/refresh {refresh_token}` rotates both; send it with the access token in `Authorization: Bearer`. A wrong refresh token ends the session.
- **Other endpoints:** `GET /auth/me`, `POST /auth/logout`, `POST /auth/password`, `POST /auth/totp/setup` then `/auth/totp/confirm`.

**OIDC (`GET /auth/oidc/{provider}/start?return_to=/path`)**
- The flow is the authorization code flow with PKCE (S256), a state value bound to the browser, and a nonce.
- The ID token is verified against the provider's JWKS (RS256 or ES256): issuer, audience, expiry and nonce.
- The account id is `<provider>.<hash of issuer and subject>`.
- `auto_create` gives first-time users `default_roles`. Otherwise an admin creates the account first (`{"oidc": {"provider", "subject"}}`).

**Routes (`<METHOD> /api/{app}/<path>`)**
- Only the routes heain-core reports to this gateway (`GET /v1/app/gateway/routes`, refreshed every `-routes-refresh`) are reachable:
  - the route must be approved in `gateway.exposures`;
  - a live instance must declare it public.
- The gateway checks, for each route:
  - **Session:** the person must be signed in, unless the route is `anonymous`.
  - **Roles:** the person must hold any of the route's roles.
  - **Rate:** at most `rate_per_min` per person, or per address for an anonymous route. The default is `-default-rate`.
- It then calls the instance over mTLS with:
  - a new trace id;
  - the lane;
  - for a signed-in person, an `X-Heain-User` assertion signed with the gateway's app key, for that app, method, path and trace.
- Only a few headers pass in either direction. Cookies, `Authorization` and any `X-Heain-*` header a client sends are never passed on.
- Every request is audited (`gateway.proxy`, with the person, route, instance and status).

**Admin (`/admin/...`, role `gateway-admin`)**
- `GET` and `POST /admin/users`; `GET`, `PUT` (name, roles, disabled) and `DELETE /admin/users/{id}`.
- `POST /admin/users/{id}/reset {password?, reset_totp?, unlock?}` and `/revoke`.
- `GET /admin/routes`.
- Changing roles or disabling an account ends that person's sessions.
- Removing an account destroys its credential key in core (crypto-shred).
- An admin cannot demote, disable or remove themselves.

**For other apps (mTLS app plane)**
- `GET /v1/gateway/routes`.
- `POST /v1/gateway/sessions/revoke {user}`: an app ends a person's sessions. This is audited (`gateway.auth`), for example for heain-consent later.

## In the app behind it

```yaml
endpoints:
  - {method: GET, path: "/v1/items/{id}", capability: demo.items, formal: true, public: true}
```

```go
u := heain.UserOf(r.Context()) // nil: a call from an app, or an anonymous route
if u == nil || !u.HasRole("clerk") { ... }
```

`examples/demo-app` is a complete example. It also checks a data-level right itself: only the person who created an item may delete it.

## Setting it up

1. Admit the app. Then through P5:
   - `gateway.apps: ["heain-gateway"]` (a security-admin's);
   - `gateway.exposures: [{app, method, path, roles, auth, rate_per_min}]` (a policy-admin's).
2. Run it:
   ```
   heain-gateway -public-cert cert.pem -public-key key.pem [-public-listen :8443] [-bootstrap-admin root] [-oidc-config oidc.json]
   ```
   - The app plane listens on 19500 (`HEAIN_LISTEN`).
   - With no account yet, `-bootstrap-admin root` creates that `gateway-admin` and writes a one-time password to `<state>/bootstrap-admin.txt` (0600).
3. OIDC providers (`-oidc-config`):
   ```json
   [{"name":"corp","issuer":"https://login.example.com","client_id":"heain","client_secret_env":"CORP_OIDC_SECRET",
     "redirect_url":"https://gw.example.com/auth/oidc/corp/callback","auto_create":true,"default_roles":["staff"]}]
   ```
   The client secret is read from the variable the file names, never from the file itself.
4. Behind a reverse proxy on the same host, `-trust-forwarded` takes the client address from `X-Forwarded-For`.

## Tests

- `go test ./...`:
  - TOTP against the RFC 6238 vectors;
  - password hashing and policy;
  - the sealed store (no plaintext on disk, crypto-shred, sessions);
  - the rate limiter;
  - OIDC against a fake provider (PKCE, nonce, audience, issuer, expiry);
  - the gateway end to end with a fake app: web, CSRF, roles, anonymous routes and rate, idle timeout, TOTP, lockout, temporary passwords, mobile rotation, admin, OIDC.
- `bash scripts/live_4_6a.sh`: against a real heain-core node with heain-database, the example app and a TEST ONLY OIDC provider (`tools/test-idp`). Needs `~/heain-core`, `~/heain-sdk`, `~/heain-database`.
- Conformance: `heain-conformance run --app . --core ~/heain-core` (heain-database as a companion; `-test-self-signed` stands in for the public certificate).

**Not yet:**
- heain-access (face, ID card) as an extra factor;
- WebAuthn;
- ACME certificates;
- a session shared between several gateway instances (sessions are per instance).
