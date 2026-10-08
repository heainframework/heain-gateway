#!/usr/bin/env bash
# heain-gateway live test B-1c (Stage B, author decisions 2026-10-08): the gateways of a zone share
# credentials and sessions, with the same mechanism as heain-database (records sealed under zone keys,
# change logs pulled between instances); a revocation is pushed at once.
#   G (18000, Master, farm registry) <- W (18003, farm Worker);
#   G: heain-database db1, heain-gateway g1 (people on 18443); W: heain-database db2, heain-gateway g2 (18453).
#  - g2 starts after g1 and does not make a second bootstrap admin: it pulls g1's accounts first;
#  - an account made on g1 signs in on g2; a web session made on g1 works on g2;
#  - sign-out on g2 ends the session on g1 at once; an admin revocation on g1 ends sessions on g2 at once;
#  - G and g1 down: people still sign in on g2;
#  - removing an account destroys its zone key: no gateway of the zone can sign it in;
#  - only heain-gateway reads a change log; no plaintext on disk.
# Needs ~/heain-core, ~/heain-sdk, ~/heain-database. ~3 min.  Run from ~/heain-gateway:  bash scripts/live_b1c.sh
set -uo pipefail
GW=$(cd "$(dirname "$0")/.." && pwd)
DBDIR=${HEAIN_DB_DIR:-$HOME/heain-database}
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/gw-b1c
URL=https://127.0.0.1:18000; WURL=https://127.0.0.1:18003
P1=https://127.0.0.1:18443; P2=https://127.0.0.1:18453
A1=https://127.0.0.1:19500; A2=https://127.0.0.1:19501
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { local who=$1; shift; curl -sk --noproxy '*' --cert "$W/$who.pem" --key "$W/$who.key" --cacert "$C/ca.pem" -H 'Content-Type: application/json' "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
until_ok() { for i in $(seq 1 ${2:-20}); do eval "$1" && return 0; sleep 0.5; done; return 1; }
runapp() { # <instance> <manifest> <port> <core-url> <core-id> <binary> [args...]
  local inst=$1 man=$2 port=$3 cu=$4 cid=$5; shift 5; mkdir -p "$W/state-$inst"
  env HEAIN_MANIFEST=$man HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$cu HEAIN_CORE_ID=$cid HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
    HEAIN_ENROLL_CORE_URL=$URL HEAIN_ENROLL_CORE_ID=G HEAIN_STATE_DIR=$W/state-$inst HEAIN_ENROLL_TOKEN=$W/$inst.tok \
    HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/app-$inst.pid"; }
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$2.tok"; }
approve_all() { for u in $URL $WURL; do
    for a in $(as approver-1 $u/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='app.register')"); do
      code approver-1 -X POST $u/v1/admin/policy/$a/approve >/dev/null; done; done; }
active() { for i in $(seq 1 60); do approve_all; [ "$(grep -c "$2: active" "$W/$1.log" 2>/dev/null)" -ge "${3:-1}" ] && return 0; sleep 1; done; return 1; }
setpol() { local id; id=$(as admin -X POST -d "{\"value\":$3}" $1/v1/admin/config/policy/$2 | j "d['action_id']"); [ -n "$id" ] && [ "$(code approver-1 -X POST $1/v1/admin/policy/$id/approve)" = 200 ]; }
client() { # <label>
  as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.json"
  python3 - "$W" "$1" <<'PY'
import json,sys; w,l=sys.argv[1],sys.argv[2]; d=json.load(open(f"{w}/{l}.json"))
open(f"{w}/{l}.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(f"{w}/{l}.boot.key","w").write(d["bootstrap_key_pem"]); open(f"{w}/{l}.token","w").write(d["token"])
PY
  openssl genrsa -out "$W/$1.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" >/dev/null 2>&1
  python3 -c "import json;print(json.dumps({'token':open('$W/$1.token').read(),'csr_pem':open('$W/$1.csr').read()}))" > "$W/$1.req"
  curl -sk --noproxy '*' --cert "$W/$1.boot.pem" --key "$W/$1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/$1.req" $URL/provision/csr \
    | python3 -c "import json,sys;open('$W/$1.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"; }
pub() { local who=$1; shift; curl -sk --noproxy '*' -b "$W/$who.jar" -c "$W/$who.jar" -H 'Content-Type: application/json' "$@"; }
pcode() { local who=$1; shift; pub "$who" -o /dev/null -w "%{http_code}" "$@"; }
login() { # <jar> <public-url> <user> <password> [extra]
  local out; out=$(pub "$1" -X POST -d "{\"username\":\"$3\",\"password\":\"$4\"${5:+,$5}}" $2/auth/login)
  echo "$out" | j "d.get('csrf_token','')" > "$W/$1.csrf"; echo "$out"; }
csrf() { cat "$W/$1.csrf" 2>/dev/null; }
cleanup() { for f in "$P"/app-*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done; true; }
trap cleanup EXIT

echo "== 0. Master G + farm Worker W; build heain-gateway and heain-database"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$T/data-W" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/public.key" -out "$W/public.pem" -days 2 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
: > "$L/G.log"; : > "$L/W.log"
startG() { nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -farm-registry-ttl=30s -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
  echo $! > "$P/G.pid"; }
startG; sleep 6
nohup "$BIN" -node-id=W -tier=WORKER -raft-addr=127.0.0.1:19003 -data-dir="$T/data-W" -http-addr=127.0.0.1:18003 \
  -cert="$C/W.pem" -key="$C/W.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=false \
  -approval-store-path="$T/data-W/approvals.db" \
  -farm-register-addr=https://127.0.0.1:18000 -farm-register-node-id=G -self-addr=https://127.0.0.1:18003 -farm-register-interval=2s >> "$L/W.log" 2>&1 &
echo $! > "$P/W.pid"; sleep 5
for u in $URL $WURL; do code admin -X PUT -d '{"value":"2s"}' $u/v1/admin/config/system/zone.sync_interval >/dev/null; done
B="GOFLAGS= GOWORK=${SDK_GOWORK:-}"
( cd "$GW" && eval "$B go build -o $W/heain-gateway ./cmd/heain-gateway" ) && ( cd "$DBDIR" && eval "$B go build -o $W/heain-database ./cmd/heain-database" ) \
  && ok "heain-gateway and heain-database build" || { bad "build"; exit 1; }
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
client ops.c1; client other.o1
for u in $URL $WURL; do setpol $u gateway.apps '["heain-gateway"]' >/dev/null; done

echo "== 1. g1 on G (bootstrap admin), then g2 on W"
token heain-database.db1 db1; token heain-gateway.g1 g1; token heain-database.db2 db2; token heain-gateway.g2 g2
runapp db1 "$DBDIR/heain-app.yaml" 19460 $URL G "$W/heain-database" -external-dialect sqlite -zone-sync-every 1s
runapp g1 "$GW/heain-app.yaml" 19500 $URL G "$W/heain-gateway" -public-listen 127.0.0.1:18443 -public-cert "$W/public.pem" -public-key "$W/public.key" \
  -bootstrap-admin root -zone-sync-every 1s
active g1 heain-gateway && ok "g1 active on G; bootstrap admin root made" || { bad "g1: $(tail -3 "$W/g1.log")"; exit 1; }
read -r _ BOOT < "$W/state-g1/bootstrap-admin.txt"
[ -n "$(login adm $P1 root "$BOOT" '"new_password":"Admin-Passphrase-2026"' | j "d['csrf_token']")" ] && ok "root signed in on g1 with its own password" || bad "root login on g1"
TMPPW=$(pub adm -X POST -H "X-CSRF-Token: $(csrf adm)" -d '{"id":"clerk1","name":"Somchai","roles":["clerk"],"password":"Clerk-Passphrase-1"}' $P1/admin/users | j "d['account']['id']")
[ "$TMPPW" = clerk1 ] && ok "root made clerk1 on g1" || bad "create clerk1"
runapp db2 "$DBDIR/heain-app.yaml" 19461 $WURL W "$W/heain-database" -external-dialect sqlite -zone-sync-every 1s
runapp g2 "$GW/heain-app.yaml" 19501 $WURL W "$W/heain-gateway" -public-listen 127.0.0.1:18453 -public-cert "$W/public.pem" -public-key "$W/public.key" \
  -bootstrap-admin root -zone-sync-every 1s
active g2 heain-gateway && ok "g2 active on W" || { bad "g2: $(tail -3 "$W/g2.log")"; exit 1; }
[ ! -e "$W/state-g2/bootstrap-admin.txt" ] && grep -q "record(s) from the other gateways of the zone" "$W/g2.log" \
  && ok "g2 pulled g1's accounts first and made no second bootstrap admin" || bad "second bootstrap: $(grep -i "zone\|bootstrap" "$W/g2.log" | tail -3)"

echo "== 2. one sign-in for the zone"
until_ok '[ -n "$(login c2 $P2 clerk1 Clerk-Passphrase-1 | j "d[\"csrf_token\"]")" ]' && ok "clerk1, made on g1, signs in on g2" || bad "clerk1 on g2: $(login c2 $P2 clerk1 Clerk-Passphrase-1)"
[ "$(pcode c1 $P1/auth/me)" = 401 ] && login c1 $P1 clerk1 Clerk-Passphrase-1 >/dev/null
until_ok '[ "$(pub c1 $P2/auth/me | j "d[\"user\"]")" = clerk1 ]' && ok "a web session made on g1 works on g2 (same cookie)" || bad "session g1 -> g2"
cp "$W/c1.jar" "$W/c1copy.jar"   # the browser forgets the cookie at sign-out; the copy keeps it to try on g1
[ "$(pcode c1 -X POST -H "X-CSRF-Token: $(csrf c1)" $P2/auth/logout)" = 200 ] && ok "clerk1 signs out on g2" || bad "logout on g2"
t0=$(date +%s%N); until_ok '[ "$(pcode c1copy $P1/auth/me)" = 401 ]' 10; t1=$(date +%s%N)
[ "$(pcode c1copy $P1/auth/me)" = 401 ] && ok "... and the same session cookie no longer works on g1 ($(( (t1-t0)/1000000 )) ms, pushed)" || bad "logout did not reach g1"
until_ok 'grep -q "a revocation was pushed" "$W/g2.log"' && ok "g2 pushed the revocation (the others pulled at once)" || bad "no push logged"
login c3 $P2 clerk1 Clerk-Passphrase-1 >/dev/null
until_ok '[ "$(pub c3 $P1/auth/me | j "d[\"user\"]")" = clerk1 ]' && ok "a session made on g2 works on g1" || bad "session g2 -> g1"
r=$(cl ops.c1 -X POST -d '{"user":"clerk1"}' $A1/v1/gateway/sessions/revoke | j "d['sessions_ended']")
until_ok '[ "$(pcode c3 $P2/auth/me)" = 401 ]' 10 && [ "${r:-0}" -ge 1 ] && ok "an app ends clerk1's sessions on g1: the session made on g2 ends there too" || bad "revoke on g1 -> g2 (ended $r)"

echo "== 3. G and g1 down: g2 keeps signing people in"
kill "$(cat "$P/app-g1.pid")" "$(cat "$P/app-db1.pid")" 2>/dev/null; kill "$(cat "$P/G.pid")"; sleep 12   # past W's 10 s certificate cache
[ -n "$(login c4 $P2 clerk1 Clerk-Passphrase-1 | j "d['csrf_token']")" ] && [ "$(pub c4 $P2/auth/me | j "d['user']")" = clerk1 ] \
  && ok "clerk1 signs in on g2 while G is down (copies on W)" || bad "sign-in while G down: $(login c4 $P2 clerk1 Clerk-Passphrase-1)"
startG; sleep 6
runapp db1 "$DBDIR/heain-app.yaml" 19460 $URL G "$W/heain-database" -external-dialect sqlite -zone-sync-every 1s
runapp g1 "$GW/heain-app.yaml" 19500 $URL G "$W/heain-gateway" -public-listen 127.0.0.1:18443 -public-cert "$W/public.pem" -public-key "$W/public.key" \
  -bootstrap-admin root -zone-sync-every 1s
active g1 heain-gateway 2 >/dev/null
until_ok '[ "$(pub c4 $P1/auth/me | j "d[\"user\"]")" = clerk1 ]' 30 && ok "G and g1 back: the session made on g2 meanwhile works on g1" || bad "catch-up on g1"

echo "== 4. removing an account"
login adm $P1 root Admin-Passphrase-2026 >/dev/null
[ "$(pcode adm -X DELETE -H "X-CSRF-Token: $(csrf adm)" $P1/admin/users/clerk1)" = 200 ] && ok "root removes clerk1 on g1 (its credential key is destroyed in the zone)" || bad "delete clerk1"
until_ok '[ "$(pcode c5 -X POST -d "{\"username\":\"clerk1\",\"password\":\"Clerk-Passphrase-1\"}" $P2/auth/login)" = 401 ]' 20 \
  && ok "clerk1 can no longer sign in on g2" || bad "deleted account still signs in on g2: $(pub c5 -X POST -d '{"username":"clerk1","password":"Clerk-Passphrase-1"}' $P2/auth/login)"
[ "$(pcode c4 $P2/auth/me)" = 401 ] && ok "and its session on g2 is gone" || bad "session after delete"

echo "== 5. only heain-gateway, nothing plaintext"
c=$(cl other.o1 -o /dev/null -w '%{http_code}' $A1/v1/gateway/replica/changes)
c2=$(cl other.o1 -o /dev/null -w '%{http_code}' -X POST $A1/v1/gateway/replica/poke)
[ "$c" = 403 ] && [ "$c2" = 403 ] && ok "another app can neither read the change log nor make a gateway pull (403)" || bad "change log to another app: $c $c2"
! grep -rqaF -e Clerk-Passphrase -e Somchai -e Admin-Passphrase "$W/state-g1" "$W/state-g2" && ok "no plaintext in either gateway's files" || bad "plaintext on disk"
[ "$(as admin "$WURL/v1/admin/audit?limit=20000" | j "any(x['event']['Action']=='app.event' and x['event']['Detail'].get('capability')=='gateway.replica' for x in d['records'])")" = True ] \
  && ok "applied changes are audited in core (gateway.replica, counts only)" || bad "replica audit"

echo "== cleanup"
cleanup; $H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(logs: $W)"
