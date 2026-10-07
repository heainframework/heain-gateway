#!/usr/bin/env bash
# heain-gateway live test 4.6a: people reach apps through heain-gateway, against a real heain-core node.
#  - heain-core lists heain-gateway in gateway.apps and exposes gateway-demo's public endpoints through P5;
#  - the bootstrap admin signs in (one-time password -> own password), sets up TOTP, creates people;
#  - a clerk signs in (web: cookie + CSRF), reaches the routes its roles allow, and the app sees the person
#    through heain-sdk's verified assertion -- which the core audit keeps and which verifies later;
#  - a manager on mobile (access + rotating refresh token); data-level rights stay the app's;
#  - anonymous route with its rate limit; a non-public endpoint is never reached; lockout after failures;
#  - an OIDC sign-in (a TEST ONLY provider), account auto-created in heain-database;
#  - an app ends a person's sessions; a disabled account is refused; sessions survive a restart;
#    nothing plaintext in the gateway's store; audit chain verifies.
# Needs ~/heain-core, ~/heain-sdk, ~/heain-database (SQLite outside store). ~2 min.
# Run from ~/heain-gateway:  bash scripts/live_4_6a.sh
set -uo pipefail
GW=$(cd "$(dirname "$0")/.." && pwd)
DBDIR=${HEAIN_DB_DIR:-$HOME/heain-database}
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/gw-4-6a
URL=https://127.0.0.1:18000
PUB=https://127.0.0.1:18443
APPGW=https://127.0.0.1:19500
DBURL=https://127.0.0.1:19460
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { local who=$1; shift; curl -sk --noproxy '*' --cert "$W/$who.pem" --key "$W/$who.key" --cacert "$C/ca.pem" "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
runapp() { # <instance> <manifest> <port> <state> <binary> [args...]
  local inst=$1 man=$2 port=$3 st=$4; shift 4; mkdir -p "$st"
  HEAIN_MANIFEST=$man HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$URL HEAIN_CORE_ID=G HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
  HEAIN_STATE_DIR=$st HEAIN_ENROLL_TOKEN=$W/$inst.tok HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/$inst.pid"; }
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$2.tok"; }
pending() { as approver-1 $URL/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='$1')"; }
approve() { code approver-1 -X POST "$URL/v1/admin/policy/$1/approve"; }
setpol() { local id; id=$(as admin -X POST -d "{\"value\":$2}" $URL/v1/admin/config/policy/$1 | j "d['action_id']"); [ -n "$id" ] && [ "$(approve $id)" = 200 ]; }
audit() { as admin "$URL/v1/admin/audit?limit=1000&from=${1:-1}"; }
client() { # <label> : a client certificate from core's provisioning
  as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.json"
  python3 - "$W" "$1" <<'PY'
import json,sys; w,l=sys.argv[1],sys.argv[2]; d=json.load(open(f"{w}/{l}.json"))
open(f"{w}/{l}.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(f"{w}/{l}.boot.key","w").write(d["bootstrap_key_pem"]); open(f"{w}/{l}.token","w").write(d["token"])
PY
  openssl genrsa -out "$W/$1.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" >/dev/null 2>&1
  python3 -c "import json;print(json.dumps({'token':open('$W/$1.token').read(),'csr_pem':open('$W/$1.csr').read()}))" > "$W/$1.req"
  curl -sk --noproxy '*' --cert "$W/$1.boot.pem" --key "$W/$1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/$1.req" $URL/provision/csr \
    | python3 -c "import json,sys;open('$W/$1.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"; }
# a person's browser (cookie jar) and its CSRF token
pub() { local who=$1; shift; curl -sk --noproxy '*' -b "$W/$who.jar" -c "$W/$who.jar" "$@"; }
pcode() { local who=$1; shift; pub "$who" -o /dev/null -w "%{http_code}" "$@"; }
csrf() { cat "$W/$1.csrf" 2>/dev/null; }
login() { # <who> <user> <password> [extra json fields] -> answer; keeps the CSRF token
  local out; out=$(pub "$1" -X POST -H 'Content-Type: application/json' -d "{\"username\":\"$2\",\"password\":\"$3\"${4:+,$4}}" $PUB/auth/login)
  echo "$out" | j "d.get('csrf_token','')" > "$W/$1.csrf"; echo "$out"; }
totpcode() { python3 - "$1" "${2:-0}" <<'PY'
import base64,hmac,hashlib,struct,sys,time
s=sys.argv[1]; k=base64.b32decode(s+"="*((8-len(s)%8)%8)); c=int(time.time())//30+int(sys.argv[2])
h=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest(); o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))
PY
}

echo "== 0. core node G; build heain-gateway, the demo app, the test provider and heain-database"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/public.key" -out "$W/public.pem" -days 2 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
B="GOFLAGS= GOWORK=${SDK_GOWORK:-}"
( cd "$GW" && eval "$B go build -o $W/heain-gateway ./cmd/heain-gateway" && eval "$B go build -o $W/demo-app ./examples/demo-app" \
  && eval "$B go build -o $W/test-idp ./tools/test-idp" ) && ok "heain-gateway, the demo app and the test provider build" || { bad "build"; exit 1; }
if [ -n "${HEAIN_DB_BIN:-}" ]; then cp "$HEAIN_DB_BIN" "$W/heain-database"; else ( cd "$DBDIR" && GOFLAGS= go build -o "$W/heain-database" ./cmd/heain-database ); fi
[ -x "$W/heain-database" ] || { bad "heain-database build"; exit 1; }
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
client ops.c1
cat > "$W/oidc.json" <<EOF
[{"name":"corp","issuer":"http://127.0.0.1:18444","client_id":"gw","client_secret_env":"GW_TEST_OIDC_SECRET",
  "redirect_url":"$PUB/auth/oidc/corp/callback","auto_create":true,"default_roles":["clerk"]}]
EOF
nohup "$W/test-idp" -listen 127.0.0.1:18444 -client-id gw -client-secret idp-s3cret >> "$W/idp.log" 2>&1 & echo $! > "$P/idp.pid"

echo "== 1. heain-database, gateway-demo and heain-gateway start and are admitted"
token heain-database.db1 db1; token gateway-demo.d1 d1; token heain-gateway.g1 g1
runapp db1 "$DBDIR/heain-app.yaml" 19460 "$W/state-db1" "$W/heain-database" -external-dialect sqlite
runapp d1 "$GW/examples/demo-app/heain-app.yaml" 19510 "$W/state-d1" "$W/demo-app"
GW_TEST_OIDC_SECRET=idp-s3cret runapp g1 "$GW/heain-app.yaml" 19500 "$W/state-g1" "$W/heain-gateway" -public-listen 127.0.0.1:18443 \
  -public-cert "$W/public.pem" -public-key "$W/public.key" -oidc-config "$W/oidc.json" -bootstrap-admin root -routes-refresh 1s
for k in $(seq 1 60); do for a in $(pending app.register); do approve $a >/dev/null; done
  grep -q "heain-gateway: active" "$W/g1.log" && grep -q "demo-app: active" "$W/d1.log" && break; sleep 1; done
grep -q "heain-gateway: active" "$W/g1.log" && grep -q "demo-app: active" "$W/d1.log" && ok "all three admitted (P5 app.register); the gateway serves people on 127.0.0.1:18443" \
  || { bad "start: $(tail -3 "$W/g1.log") / $(tail -2 "$W/d1.log") / $(tail -2 "$W/db1.log")"; $H stop-all >/dev/null 2>&1; exit 1; }
[ -s "$W/state-g1/bootstrap-admin.txt" ] && ok "bootstrap admin root created; its one-time password is in the state directory (0$(stat -c %a "$W/state-g1/bootstrap-admin.txt"))" || bad "bootstrap file"

echo "== 2. heain-core: heain-gateway trusted (security-admin) and gateway-demo's routes exposed (policy-admin), through P5"
setpol gateway.apps '["heain-gateway"]' && ok "gateway.apps [heain-gateway] approved" || bad "gateway.apps"
setpol gateway.exposures '[{"app":"gateway-demo","method":"GET","path":"/v1/items/{id}","roles":["clerk","manager"]},
 {"app":"gateway-demo","method":"POST","path":"/v1/items","roles":["clerk","manager"]},
 {"app":"gateway-demo","method":"DELETE","path":"/v1/items/{id}","roles":["manager"]},
 {"app":"gateway-demo","method":"GET","path":"/v1/hello","auth":"anonymous","rate_per_min":3},
 {"app":"gateway-demo","method":"GET","path":"/v1/internal","roles":["clerk"]}]' && ok "gateway.exposures (5 routes) approved" || bad "exposures"
for k in $(seq 1 20); do [ "$(cl ops.c1 $APPGW/v1/gateway/routes | j "len([r for r in d['routes'] if r['status']=='ok'])")" = 4 ] && break; sleep 1; done
r=$(cl ops.c1 $APPGW/v1/gateway/routes | j "sorted((x['method']+' '+x['path'],x['status']) for x in d['routes'])")
[ "$r" = "[('DELETE /v1/items/{id}', 'ok'), ('GET /v1/hello', 'ok'), ('GET /v1/internal', 'not_public'), ('GET /v1/items/{id}', 'ok'), ('POST /v1/items', 'ok')]" ] \
  && ok "the gateway sees 4 routes ok; GET /v1/internal not_public (the app does not declare it)" || bad "routes: $r"

echo "== 3. the bootstrap admin: own password, TOTP, people"
read -r _ BOOT < "$W/state-g1/bootstrap-admin.txt"
[ "$(login adm root "$BOOT" | j "d['error']['code']")" = password_change_required ] && ok "the one-time password must be replaced at the first sign-in" || bad "must change"
[ -n "$(login adm root "$BOOT" '"new_password":"Admin-Passphrase-2026"' | j "d['csrf_token']")" ] && ok "root signed in with a new password (web session: HttpOnly cookie + CSRF token)" || bad "root login"
SEC=$(pub adm -X POST -H "X-CSRF-Token: $(csrf adm)" -d '{"password":"Admin-Passphrase-2026"}' $PUB/auth/totp/setup | j "d['secret']")
[ "$(pub adm -X POST -H "X-CSRF-Token: $(csrf adm)" -d "{\"code\":\"$(totpcode "$SEC")\"}" $PUB/auth/totp/confirm | j "d['status']")" = totp_on ] && ok "root set up an authenticator (TOTP)" || bad "totp"
[ "$(login adm root Admin-Passphrase-2026 | j "d['error']['code']")" = totp_required ] && ok "root's next sign-in asks for the code" || bad "totp required"
sleep_to_next() { sleep $(( 31 - $(date +%s) % 30 )); }
sleep_to_next
[ -n "$(login adm root Admin-Passphrase-2026 "\"totp\":\"$(totpcode "$SEC")\"" | j "d['csrf_token']")" ] && [ "$(pub adm $PUB/auth/me | j "d['amr']")" = pwd+totp ] && ok "with the code: signed in (amr pwd+totp)" || bad "totp login"
TMP=$(pub adm -X POST -H "X-CSRF-Token: $(csrf adm)" -d '{"id":"clerk1","name":"Somchai","roles":["clerk"]}' $PUB/admin/users | j "d['temporary_password']")
[ "$(pub adm -X POST -H "X-CSRF-Token: $(csrf adm)" -d '{"id":"mgr1","name":"Malee","roles":["clerk","manager"],"password":"Malee-Passphrase-1"}' $PUB/admin/users | j "d['account']['id']")" = mgr1 ] \
  && [ -n "$TMP" ] && ok "root created clerk1 (temporary password) and mgr1 (clerk, manager)" || bad "create users"
[ "$(pcode adm -X POST -d '{"id":"x9","roles":[]}' $PUB/admin/users)" = 403 ] && ok "an admin change without the CSRF token is refused" || bad "admin csrf"
r=$(cl ops.c1 "$DBURL/v1/accounts/person:clerk1" | j "(d['role'],d['metadata_kv']['roles'],d['metadata_kv']['source'])")
[ "$r" = "('person', 'clerk', 'local')" ] && ok "the account record lives in heain-database (person:clerk1, roles clerk); the credential does not" || bad "db record: $r"
cl ops.c1 "$DBURL/v1/accounts/person:clerk1" | grep -qi "pbkdf2\|password" && bad "credential in heain-database" || true

echo "== 4. a clerk on the web"
login clk clerk1 "$TMP" '"new_password":"Clerk-Passphrase-1"' > /dev/null
r=$(pub clk -H 'X-Heain-User: forged' "$PUB/api/gateway-demo/v1/items/7?x=1")
[ "$(echo "$r" | j "(d['user'],d['roles'],d['gateway'],d['item'],d['query'],d['amr'])")" = "('clerk1', ['clerk'], 'heain-gateway.g1', '7', 'x=1', 'pwd')" ] \
  && ok "GET /api/gateway-demo/v1/items/7: the app sees clerk1 (roles clerk) vouched for by heain-gateway.g1; a forged X-Heain-User from the client is dropped" || bad "get: $r"
[ "$(pcode clk -X POST -d '{"id":"c-1"}' $PUB/api/gateway-demo/v1/items)" = 403 ] && ok "POST without the CSRF token: refused" || bad "csrf"
[ "$(pub clk -X POST -H "X-CSRF-Token: $(csrf clk)" -d '{"id":"c-1"}' $PUB/api/gateway-demo/v1/items | j "d['created']")" = c-1 ] && ok "POST with it: item c-1 created by clerk1" || bad "post"
[ "$(pcode clk -X DELETE -H "X-CSRF-Token: $(csrf clk)" $PUB/api/gateway-demo/v1/items/c-1)" = 403 ] && ok "DELETE needs manager: refused at the gateway" || bad "role"
[ "$(pcode clk $PUB/api/gateway-demo/v1/internal)" = 503 ] && ok "GET /v1/internal is exposed but not declared public: never reached (503)" || bad "internal"
[ "$(pcode clk $PUB/api/gateway-demo/v1/nothing)" = 404 ] && [ "$(pcode clk "$PUB/api/gateway-demo/v1/items/..%2f..%2fx")" != 200 ] && ok "unknown routes 404; no path tricks" || bad "404"
AU=$(pub anon -H 'X-Heain-User: forged' $PUB/api/gateway-demo/v1/hello | j "d['user']"); for i in 2 3; do pub anon $PUB/api/gateway-demo/v1/hello >/dev/null; done
[ "$(pcode anon $PUB/api/gateway-demo/v1/hello)" = 429 ] && [ "$(curl -sk --noproxy '*' $PUB/api/gateway-demo/v1/items/1 -o /dev/null -w '%{http_code}')" = 401 ] \
  && ok "anonymous route: no sign-in needed, 3 a minute then 429; a user route without a session: 401" || bad "anonymous"
[ "$AU" = None ] && ok "an anonymous route carries no person (a forged X-Heain-User is dropped)" || bad "anon user: $AU"

echo "== 5. the proof in core's audit"
for k in $(seq 1 10); do audit | j "[x for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Actor']=='gateway-demo.d1' and (x['event']['Detail'].get('detail') or {}).get('user')=='clerk1']" | grep -q user_assertion && break; sleep 1; done
audit | python3 -c "
import json,sys,base64
d=json.load(sys.stdin)
for x in d['records']:
    e=x['event']
    if e['Action']=='app.event' and e['Actor']=='gateway-demo.d1' and (e['Detail'].get('detail') or {}).get('user')=='clerk1':
        a=e['Detail']['detail']['user_assertion']; print(a); break
" > "$W/assertion.txt"
python3 - "$W" <<'PY'
import json,base64,sys
w=sys.argv[1]; v=open(w+"/assertion.txt").read().strip(); v+= "="*((4-len(v)%4)%4)
a=json.loads(base64.urlsafe_b64decode(v)); sig=base64.b64decode(a.pop("sig"))
open(w+"/assertion.sig","wb").write(sig); open(w+"/assertion.canon","wb").write(json.dumps(a,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())
open(w+"/assertion.json","w").write(json.dumps(a))
PY
openssl x509 -in "$W/state-g1/app.pem" -pubkey -noout > "$W/gw.pub" 2>/dev/null
v=$(openssl dgst -sha256 -verify "$W/gw.pub" -signature "$W/assertion.sig" "$W/assertion.canon" 2>&1)
[ "$v" = "Verified OK" ] && [ "$(j "(d['sub'],d['iss'],d['aud'])" < "$W/assertion.json")" = "('clerk1', 'heain-gateway.g1', 'gateway-demo')" ] \
  && ok "gateway-demo's audit event in core keeps the signed assertion: it verifies with heain-gateway.g1's certificate (sub clerk1)" || bad "assertion proof: $v $(cat "$W/assertion.json" 2>/dev/null)"
n=$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail']['capability']=='gateway.proxy' and x['event']['Detail']['detail'].get('user')=='clerk1')")
m=$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail']['capability']=='gateway.auth')")
[ "${n:-0}" -ge 4 ] && [ "${m:-0}" -ge 6 ] && ok "the gateway audited clerk1's requests ($n) and the sign-ins and admin actions ($m)" || bad "gateway audit: $n $m"
audit | grep -q "Clerk-Passphrase-1\|Admin-Passphrase" && bad "a password in the audit" || ok "no password in the audit chain"

echo "== 6. a manager on mobile; the app's own data-level check"
r=$(curl -sk --noproxy '*' -X POST -d '{"username":"mgr1","password":"Malee-Passphrase-1","client":"mobile"}' $PUB/auth/login)
AT=$(echo "$r" | j "d['access_token']"); RT=$(echo "$r" | j "d['refresh_token']")
mob() { curl -sk --noproxy '*' -H "Authorization: Bearer $AT" "$@"; }
[ -n "$AT" ] && [ "$(mob -X POST -d '{"id":"m-1"}' $PUB/api/gateway-demo/v1/items | j "d['created']")" = m-1 ] && ok "mgr1 signed in on mobile (bearer, no CSRF needed) and created m-1" || bad "mobile: $r"
[ "$(mob -X DELETE $PUB/api/gateway-demo/v1/items/c-1 | j "d['error']['code']")" = not_yours ] && ok "mgr1 may DELETE (manager) but not clerk1's item: the app refuses (not_yours)" || bad "data-level"
[ "$(mob -X DELETE $PUB/api/gateway-demo/v1/items/m-1 | j "d['deleted']")" = m-1 ] && ok "mgr1 deletes its own item" || bad "own delete"
r=$(mob -X POST -d "{\"refresh_token\":\"$RT\"}" $PUB/auth/refresh); AT2=$(echo "$r" | j "d['access_token']"); RT2=$(echo "$r" | j "d['refresh_token']")
[ -n "$AT2" ] && [ "$RT2" != "$RT" ] && [ "$(mob $PUB/auth/me -o /dev/null -w '%{http_code}')" = 401 ] && ok "refresh rotates both tokens; the old access token is dead" || bad "refresh: $r"
AT=$AT2

echo "== 7. lockout"
for i in 1 2 3 4 5; do curl -sk --noproxy '*' -X POST -d '{"username":"clerk1","password":"wrong-guess-123"}' $PUB/auth/login >/dev/null; done
[ "$(curl -sk --noproxy '*' -X POST -d '{"username":"clerk1","password":"Clerk-Passphrase-1"}' $PUB/auth/login | j "d['error']['code']")" = locked ] && ok "5 wrong passwords: clerk1 locked (even with the right one)" || bad "lock"
[ "$(pub adm -X POST -H "X-CSRF-Token: $(csrf adm)" -d '{"unlock":true}' $PUB/admin/users/clerk1/reset | j "d['status']")" = reset ] && [ -n "$(login clk clerk1 Clerk-Passphrase-1 | j "d['csrf_token']")" ] && ok "root unlocked clerk1; signed in again" || bad "unlock"

echo "== 8. OIDC (TEST ONLY provider)"
L1=$(pub oi -o /dev/null -w '%{redirect_url}' "$PUB/auth/oidc/corp/start?return_to=/welcome")
L2=$(curl -s --noproxy '*' -o /dev/null -w '%{redirect_url}' "$L1&login_hint=alice")
L3=$(pub oi -o /dev/null -w '%{redirect_url}' "$L2")
r=$(pub oi $PUB/auth/me)
[ "$L3" = "$PUB/welcome" ] && [ "$(echo "$r" | j "(d['amr'],d['name'],d['roles'])")" = "('oidc:corp', 'Test alice', ['clerk'])" ] && ok "alice signed in through the provider (code + PKCE, state bound to the browser), account auto-created as clerk" || bad "oidc: $L1 / $L3 / $r"
AL=$(echo "$r" | j "d['user']")
[ "$(pub oi $PUB/api/gateway-demo/v1/items/5 | j "d['user']")" = "$AL" ] && ok "alice ($AL) reaches the clerk route" || bad "oidc route"
[ "$(cl ops.c1 "$DBURL/v1/accounts/person:$AL" | j "d['metadata_kv']['source']")" = oidc:corp ] && ok "alice's account record is in heain-database (source oidc:corp)" || bad "oidc record"
[ "$(pcode oi2 "$PUB/auth/oidc/corp/callback?code=x&state=$(echo "$L2" | sed 's/.*state=\([^&]*\).*/\1/')")" = 400 ] && ok "a callback in another browser is refused (state)" || bad "state"

echo "== 9. an app ends a person's sessions; a disabled account"
[ "$(cl ops.c1 -X POST -d "{\"user\":\"$AL\"}" $APPGW/v1/gateway/sessions/revoke | j "d['sessions_ended']")" = 1 ] && [ "$(pcode oi $PUB/auth/me)" = 401 ] \
  && ok "an app (ops.c1) ended alice's session through the app plane (gateway.auth, audited)" || bad "revoke"
[ "$(pub adm -X PUT -H "X-CSRF-Token: $(csrf adm)" -d '{"disabled":true}' $PUB/admin/users/mgr1 | j "d['sessions_ended']")" = 1 ] && [ "$(mob $PUB/auth/me -o /dev/null -w '%{http_code}')" = 401 ] \
  && [ "$(curl -sk --noproxy '*' -X POST -d '{"username":"mgr1","password":"Malee-Passphrase-1"}' $PUB/auth/login | j "d['error']['code']")" = account_disabled ] \
  && ok "root disabled mgr1: its mobile session ended, sign-in refused" || bad "disable"

echo "== 10. restart; nothing plaintext at rest"
kill "$(cat "$P/g1.pid")"; sleep 2
GW_TEST_OIDC_SECRET=idp-s3cret runapp g1 "$GW/heain-app.yaml" 19500 "$W/state-g1" "$W/heain-gateway" -public-listen 127.0.0.1:18443 \
  -public-cert "$W/public.pem" -public-key "$W/public.key" -oidc-config "$W/oidc.json" -bootstrap-admin root -routes-refresh 1s
for k in $(seq 1 30); do [ "$(grep -c "heain-gateway: active" "$W/g1.log")" -ge 2 ] && break; sleep 1; done
[ "$(pub clk $PUB/auth/me | j "d['user']")" = clerk1 ] && [ "$(grep -c "bootstrap admin" "$W/g1.log")" = 1 ] && ok "after a restart clerk1's session still holds; no second bootstrap" || bad "restart"
s=$(python3 -c "import sys;b=open(sys.argv[1],'rb').read();print(sum(b.count(x.encode()) for x in sys.argv[2:]))" "$W/state-g1/gateway.db" clerk1 Clerk-Passphrase pbkdf2 "$SEC")
[ "$s" = 0 ] && ok "gateway.db holds no account name, password, hash or TOTP secret in plaintext" || bad "plaintext: $s"
for n in $URL; do v=$(as admin "$n/v1/admin/audit/verify" | j "d['ok']"); [ "$v" = True ] || bad "audit verify"; done; ok "audit chain verifies"

echo "== cleanup"
kill "$(cat "$P/idp.pid")" 2>/dev/null
$H stop-all >/dev/null 2>&1
for f in "$P"/db1.pid "$P"/d1.pid "$P"/g1.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(logs: $W)"
