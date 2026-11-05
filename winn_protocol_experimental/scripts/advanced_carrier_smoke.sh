#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-advanced-carrier.XXXXXX")
BIN_DIR="$WORK_DIR/bin"
PKI_DIR="$WORK_DIR/pki"
ISSUER_PORT=${WINN_ISSUER_PORT:-19544}
CARRIER_PORT=${WINN_ADVANCED_CARRIER_PORT:-19545}
METRICS_PORT=${WINN_ADVANCED_METRICS_PORT:-19546}
BACKEND_PORT=${WINN_ADVANCED_BACKEND_PORT:-19547}
LOCAL_PORT=${WINN_ADVANCED_LOCAL_PORT:-19548}
# Source port of the simulated local AWG client. Production runs must name the
# allowed local peer, so this suite binds a fixed port and passes it, the way a
# real AWG client with a fixed listen port does.
LOCAL_PEER_PORT=${WINN_ADVANCED_LOCAL_PEER_PORT:-19549}
ISSUER_PID=""
CARRIER_PID=""
CLIENT_PID=""
ECHO_PID=""
CONTAINER_NAME="winn-advanced-carrier-postgres-$$"
CONTAINER_ID=""
PG_TLS_DIR="$WORK_DIR/pg-tls"
POSTGRES_DSN_FILE="$WORK_DIR/privacy-token-postgres.dsn"
umask 077

cleanup() {
  for process_id in "$CLIENT_PID" "$CARRIER_PID" "$ISSUER_PID" "$ECHO_PID"; do
    if [ -n "$process_id" ]; then
      kill "$process_id" 2>/dev/null || true
      wait "$process_id" 2>/dev/null || true
    fi
  done
  if [ -n "$CONTAINER_ID" ]; then
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  rm -r "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$BIN_DIR"
cd "$ROOT_DIR"
for command in winn-pki winn-manifest winn-token-issuer winn-token winn-carrier-server winn-carrier-client winn-audit; do
  "$GO_BIN" build -o "$BIN_DIR/$command" "./cmd/$command"
done
"$BIN_DIR/winn-pki" \
  -out "$PKI_DIR" \
  -server-name 127.0.0.1 \
  -device-id advanced-smoke-1 >/dev/null

MANIFEST="$WORK_DIR/gateway-manifest.json"
TRANSPARENCY_LOG="$WORK_DIR/transparency.jsonl"
CHECKPOINT="$WORK_DIR/transparency-checkpoint.json"
"$BIN_DIR/winn-manifest" \
  -action create \
  -out "$MANIFEST" \
  -controller-id carrier-controller-1 \
  -controller-pq-seed "$PKI_DIR/controller-mldsa87.seed" \
  -node-id node-a \
  -masque-template "https://127.0.0.1:$CARRIER_PORT/.well-known/masque/udp/{target_host}/{target_port}/" \
  -h2-url "https://127.0.0.1:$CARRIER_PORT/winn/v2/udp-stream" \
  -server-name 127.0.0.1 \
  -ech-config-list "$PKI_DIR/ech-config-list.bin" \
  -authorization-modes identity,anonymous-token \
  -privacy-token-public-key "$PKI_DIR/privacy-token-issuer-public.pem" \
  -privacy-token-scope carrier:winn.invalid:443 >/dev/null
"$BIN_DIR/winn-manifest" \
  -action append \
  -manifest "$MANIFEST" \
  -controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
  -controller-pq-seed "$PKI_DIR/controller-mldsa87.seed" \
  -transparency-log "$TRANSPARENCY_LOG" \
  -checkpoint "$CHECKPOINT" >/dev/null
"$BIN_DIR/winn-manifest" \
  -action verify-log \
  -manifest "$MANIFEST" \
  -controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
  -transparency-log "$TRANSPARENCY_LOG" \
  -checkpoint "$CHECKPOINT" >/dev/null

"$BIN_DIR/winn-token-issuer" \
  -addr "127.0.0.1:$ISSUER_PORT" \
  -cert "$PKI_DIR/server.pem" \
  -key "$PKI_DIR/server-key.pem" \
  -client-ca "$PKI_DIR/ca.pem" \
  -device-registry "$PKI_DIR/device-pq-registry.json" \
  -privacy-token-private-key "$PKI_DIR/privacy-token-issuer-key.pem" \
  -ech-keys "$PKI_DIR/ech-server-keys.json" \
  -audit-log "$WORK_DIR/issuer-audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" \
  -insecure-cover-reuses-winn-leaf >"$WORK_DIR/issuer.log" 2>&1 &
ISSUER_PID=$!

issue_token() {
  output=$1
  attempts=0
  until "$BIN_DIR/winn-token" \
    -issuer-url "https://127.0.0.1:$ISSUER_PORT/winn/v1/privacy-token" \
    -privacy-token-public-key "$PKI_DIR/privacy-token-issuer-public.pem" \
    -out "$output" \
    -cert "$PKI_DIR/device.pem" \
    -key "$PKI_DIR/device-key.pem" \
    -root-ca "$PKI_DIR/ca.pem" \
    -server-name 127.0.0.1 \
    -device-id advanced-smoke-1 \
    -device-pq-seed "$PKI_DIR/device-mldsa65.seed" \
    -ech-config-list "$PKI_DIR/ech-config-list.bin" >>"$WORK_DIR/token-client.log" 2>&1; do
    if ! kill -0 "$ISSUER_PID" 2>/dev/null; then
      sed -n '1,200p' "$WORK_DIR/issuer.log" >&2
      exit 1
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 100 ]; then
      sed -n '1,200p' "$WORK_DIR/issuer.log" >&2
      sed -n '1,200p' "$WORK_DIR/token-client.log" >&2
      echo "privacy-token issuer readiness timeout" >&2
      exit 1
    fi
    sleep 0.05
  done
}

issue_token "$WORK_DIR/token-1.json"
issue_token "$WORK_DIR/token-2.json"

python3 -c 'import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("127.0.0.1",int(sys.argv[1])))
while True:
 data,peer=s.recvfrom(2048)
 s.sendto(data,peer)' "$BACKEND_PORT" >"$WORK_DIR/echo.log" 2>&1 &
ECHO_PID=$!

# Durable single-use privacy-token redemption now requires a private PostgreSQL
# that meets the production sslmode=verify-full bar. Bring up a disposable,
# TLS-secured postgres:18-alpine using the same pattern as
# scripts/postgres_test.sh, but with a locally generated certificate so the
# carrier server authorizes anonymous tokens against a real, transport-encrypted
# redemption ledger instead of an unreachable insecure-loopback escape hatch.
CONTAINER_ID=$(
  docker run --rm -d \
    --name "$CONTAINER_NAME" \
    -e POSTGRES_USER=winn_test \
    -e POSTGRES_PASSWORD=winn_test_password \
    -e POSTGRES_DB=winn_test \
    -p 127.0.0.1::5432 \
    postgres:18-alpine
)

attempts=0
until docker exec "$CONTAINER_NAME" \
  psql -U winn_test -d winn_test -c 'SELECT 1' >/dev/null 2>&1; do
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 120 ]; then
    docker logs "$CONTAINER_NAME" >&2
    echo "disposable PostgreSQL readiness timeout" >&2
    exit 1
  fi
  sleep 0.25
done

# Self-signed leaf that doubles as its own trust root, with a Subject
# Alternative Name for the loopback IP the DSN connects through so
# sslmode=verify-full hostname verification succeeds.
mkdir -p "$PG_TLS_DIR"
if ! openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$PG_TLS_DIR/server.key" \
  -out "$PG_TLS_DIR/server.crt" \
  -days 1 \
  -subj "/CN=winn-advanced-carrier-smoke-postgres" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" \
  -addext "extendedKeyUsage=serverAuth" \
  >"$PG_TLS_DIR/openssl.log" 2>&1; then
  cat "$PG_TLS_DIR/openssl.log" >&2
  echo "failed to generate disposable PostgreSQL TLS certificate" >&2
  exit 1
fi

# Install server.crt/server.key into the data directory and hand ownership to
# the in-container postgres user. A group/other-readable private key makes the
# server refuse to enable SSL, so copy the files in and fix ownership/mode
# rather than fighting host bind-mount permission mapping.
PG_DATA_DIR=$(
  docker exec "$CONTAINER_NAME" \
    psql -U winn_test -d winn_test -Atc 'SHOW data_directory'
)
docker cp "$PG_TLS_DIR/server.crt" "$CONTAINER_NAME:$PG_DATA_DIR/server.crt"
docker cp "$PG_TLS_DIR/server.key" "$CONTAINER_NAME:$PG_DATA_DIR/server.key"
docker exec -u 0 "$CONTAINER_NAME" sh -c \
  "chown postgres:postgres '$PG_DATA_DIR/server.crt' '$PG_DATA_DIR/server.key' && \
   chmod 644 '$PG_DATA_DIR/server.crt' && \
   chmod 600 '$PG_DATA_DIR/server.key'"

# ssl is a SIGHUP-reloadable setting, so enable it once the key is in place.
docker exec "$CONTAINER_NAME" \
  psql -U winn_test -d winn_test -v ON_ERROR_STOP=1 \
  -c 'ALTER SYSTEM SET ssl = on;' \
  -c 'SELECT pg_reload_conf();' >/dev/null

attempts=0
until [ "$(docker exec "$CONTAINER_NAME" \
  psql -U winn_test -d winn_test -Atc 'SHOW ssl' 2>/dev/null)" = on ]; do
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 40 ]; then
    docker logs "$CONTAINER_NAME" >&2
    echo "disposable PostgreSQL TLS did not come up" >&2
    exit 1
  fi
  sleep 0.25
done

HOST_PORT=$(docker port "$CONTAINER_NAME" 5432/tcp | awk -F: 'NR == 1 {print $NF}')
if [ -z "$HOST_PORT" ]; then
  echo "could not resolve disposable PostgreSQL port" >&2
  exit 1
fi

docker exec -i "$CONTAINER_NAME" \
  psql -v ON_ERROR_STOP=1 -U winn_test -d winn_test \
  <"$ROOT_DIR/schema/postgres_v1.sql" >/dev/null

printf '%s\n' \
  "postgres://winn_test:winn_test_password@127.0.0.1:$HOST_PORT/winn_test?sslmode=verify-full&sslrootcert=$PG_TLS_DIR/server.crt" \
  >"$POSTGRES_DSN_FILE"

"$BIN_DIR/winn-carrier-server" \
  -addr "127.0.0.1:$CARRIER_PORT" \
  -metrics-addr "127.0.0.1:$METRICS_PORT" \
  -public-target winn.invalid:443 \
  -awg-backend "127.0.0.1:$BACKEND_PORT" \
  -cert "$PKI_DIR/server.pem" \
  -key "$PKI_DIR/server-key.pem" \
  -controller-pq-seed "$PKI_DIR/controller-mldsa87.seed" \
  -audit-log "$WORK_DIR/carrier-audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" \
  -ech-keys "$PKI_DIR/ech-server-keys.json" \
  -authorization-mode anonymous-token \
  -privacy-token-postgres-dsn-file "$POSTGRES_DSN_FILE" \
  -gateway-manifest "$MANIFEST" \
  -node-id node-a \
  -controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
  -transparency-log "$TRANSPARENCY_LOG" \
  -transparency-checkpoint "$CHECKPOINT" \
  -insecure-cover-reuses-winn-leaf >"$WORK_DIR/carrier.log" 2>&1 &
CARRIER_PID=$!

attempts=0
until curl --fail --silent "http://127.0.0.1:$METRICS_PORT/readyz" >/dev/null 2>&1; do
  if ! kill -0 "$CARRIER_PID" 2>/dev/null; then
    sed -n '1,200p' "$WORK_DIR/carrier.log" >&2
    exit 1
  fi
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 100 ]; then
    echo "anonymous carrier readiness timeout" >&2
    exit 1
  fi
  sleep 0.05
done

"$BIN_DIR/winn-carrier-client" \
  -gateway-manifest "$MANIFEST" \
  -node-id node-a \
  -transparency-log "$TRANSPARENCY_LOG" \
  -transparency-checkpoint "$CHECKPOINT" \
  -controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
  -root-ca "$PKI_DIR/ca.pem" \
  -authorization-mode anonymous-token \
  -privacy-token-bundle "$WORK_DIR/token-1.json" \
  -privacy-token-bundle "$WORK_DIR/token-2.json" \
  -privacy-profile high-risk \
  -enable-cover-traffic \
  -cover-interval-min 500ms \
  -cover-interval-max 700ms \
  -public-target winn.invalid:443 \
  -local "127.0.0.1:$LOCAL_PORT" \
  -local-peer "127.0.0.1:$LOCAL_PEER_PORT" \
  -metrics-addr "" \
  -session-id 11223344556677889900aabbccddeeff \
  -connect-timeout 5s >"$WORK_DIR/client.log" 2>&1 &
CLIENT_PID=$!

attempts=0
until grep -q "active=node-a-h3" "$WORK_DIR/client.log"; do
  if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    sed -n '1,200p' "$WORK_DIR/client.log" >&2
    exit 1
  fi
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 100 ]; then
    sed -n '1,200p' "$WORK_DIR/client.log" >&2
    echo "anonymous carrier client readiness timeout" >&2
    exit 1
  fi
  sleep 0.05
done

# A co-resident process races the real AWG client and sends FIRST. Without an
# expected local peer the relay pins whoever arrives first for the connection
# lifetime, so this sender would capture the tunnel: the real client is denied
# service and the impostor receives all carrier-to-local packet cadence, a
# local oracle that the user is running this tool. The order matters - if the
# legitimate peer went first it would win the race either way and this would
# prove nothing.
if python3 -c 'import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b"co-resident-impostor",("127.0.0.1",int(sys.argv[1])))
try:
    s.recvfrom(2048)
except socket.timeout:
    sys.exit(1)
sys.exit(0)' "$LOCAL_PORT"; then
  echo "relay served a local sender other than -local-peer" >&2
  exit 1
fi

# The configured peer must still be served after losing that race.
response=$(
  python3 -c 'import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("127.0.0.1",int(sys.argv[2])))
s.settimeout(3)
s.sendto(b"anonymous-carrier-ok",("127.0.0.1",int(sys.argv[1])))
reply,_=s.recvfrom(2048)
sys.stdout.write(reply.decode())' "$LOCAL_PORT" "$LOCAL_PEER_PORT"
)
test "$response" = anonymous-carrier-ok
kill "$CLIENT_PID"
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

if "$BIN_DIR/winn-carrier-client" \
  -gateway-manifest "$MANIFEST" \
  -node-id node-a \
  -transparency-log "$TRANSPARENCY_LOG" \
  -transparency-checkpoint "$CHECKPOINT" \
  -controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
  -root-ca "$PKI_DIR/ca.pem" \
  -authorization-mode anonymous-token \
  -privacy-token-bundle "$WORK_DIR/token-1.json" \
  -public-target winn.invalid:443 \
  -local "127.0.0.1:$LOCAL_PORT" \
  -local-peer "127.0.0.1:$LOCAL_PEER_PORT" \
  -metrics-addr "" \
  -connect-timeout 1s >"$WORK_DIR/replay.log" 2>&1; then
  echo "redeemed privacy token was accepted twice" >&2
  exit 1
fi

"$BIN_DIR/winn-audit" \
  -audit-log "$WORK_DIR/issuer-audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" >/dev/null
"$BIN_DIR/winn-audit" \
  -audit-log "$WORK_DIR/carrier-audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" >/dev/null

echo "PASS: signed transparent manifest, mandatory ECH, blind split-trust issuance, anonymous H3 carrier, high-risk padding/cover, and one-time redemption"
