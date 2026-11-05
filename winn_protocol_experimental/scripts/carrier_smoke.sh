#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-carrier-smoke.XXXXXX")
BIN_DIR="$WORK_DIR/bin"
PKI_DIR="$WORK_DIR/pki"
CARRIER_PORT=${WINN_CARRIER_PORT:-19445}
METRICS_PORT=${WINN_CARRIER_METRICS_PORT:-19446}
BACKEND_PORT=${WINN_CARRIER_BACKEND_PORT:-19447}
LOCAL_PORT=${WINN_CARRIER_LOCAL_PORT:-19448}
ECHO_PID=""
SERVER_PID=""
CLIENT_PID=""

cleanup() {
  for process_id in "$CLIENT_PID" "$SERVER_PID" "$ECHO_PID"; do
    if [ -n "$process_id" ]; then
      kill "$process_id" 2>/dev/null || true
      wait "$process_id" 2>/dev/null || true
    fi
  done
  rm -r "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$BIN_DIR"
cd "$ROOT_DIR"
"$GO_BIN" build -o "$BIN_DIR/winn-pki" ./cmd/winn-pki
"$GO_BIN" build -o "$BIN_DIR/winn-carrier-server" ./cmd/winn-carrier-server
"$GO_BIN" build -o "$BIN_DIR/winn-carrier-client" ./cmd/winn-carrier-client
"$GO_BIN" build -o "$BIN_DIR/winn-audit" ./cmd/winn-audit
"$BIN_DIR/winn-pki" -out "$PKI_DIR" -server-name 127.0.0.1 -device-id carrier-smoke-1 >/dev/null

python3 -c 'import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("127.0.0.1",int(sys.argv[1])))
while True:
 data,peer=s.recvfrom(2048)
 s.sendto(data,peer)' "$BACKEND_PORT" >"$WORK_DIR/echo.log" 2>&1 &
ECHO_PID=$!

"$BIN_DIR/winn-carrier-server" \
  -addr "127.0.0.1:$CARRIER_PORT" \
  -metrics-addr "127.0.0.1:$METRICS_PORT" \
  -masque-template "https://127.0.0.1:$CARRIER_PORT/.well-known/masque/udp/{target_host}/{target_port}/" \
  -public-target winn.invalid:443 \
  -awg-backend "127.0.0.1:$BACKEND_PORT" \
  -cert "$PKI_DIR/server.pem" \
  -key "$PKI_DIR/server-key.pem" \
  -client-ca "$PKI_DIR/ca.pem" \
  -device-registry "$PKI_DIR/device-pq-registry.json" \
  -controller-pq-seed "$PKI_DIR/controller-mldsa87.seed" \
  -controller-id carrier-controller-1 \
  -suite x25519-mlkem768 \
  -ech-keys "$PKI_DIR/ech-server-keys.json" \
  -audit-log "$WORK_DIR/carrier-audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" \
  -lab-mode >"$WORK_DIR/server.log" 2>&1 &
SERVER_PID=$!

attempt=0
until curl --fail --silent "http://127.0.0.1:$METRICS_PORT/readyz" >/dev/null 2>&1; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    sed -n '1,160p' "$WORK_DIR/server.log" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo "carrier server readiness timeout" >&2
    exit 1
  fi
  sleep 0.05
done

run_client() {
  carrier_order=$1
  expected_path=$2
  : >"$WORK_DIR/client.log"
  "$BIN_DIR/winn-carrier-client" \
    -masque-template "https://127.0.0.1:$CARRIER_PORT/.well-known/masque/udp/{target_host}/{target_port}/" \
    -h2-url "https://127.0.0.1:$CARRIER_PORT/winn/v2/udp-stream" \
    -public-target winn.invalid:443 \
    -local "127.0.0.1:$LOCAL_PORT" \
    -metrics-addr "" \
    -cert "$PKI_DIR/device.pem" \
    -key "$PKI_DIR/device-key.pem" \
    -root-ca "$PKI_DIR/ca.pem" \
    -server-name 127.0.0.1 \
    -device-id carrier-smoke-1 \
    -device-pq-seed "$PKI_DIR/device-mldsa65.seed" \
    -controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
    -controller-id carrier-controller-1 \
    -suite x25519-mlkem768 \
    -ech-config-list "$PKI_DIR/ech-config-list.bin" \
    -session-id 00112233445566778899aabbccddeeff \
    -tunnel-generation 7 \
    -carriers "$carrier_order" \
    -lab-mode >"$WORK_DIR/client.log" 2>&1 &
  CLIENT_PID=$!
  attempt=0
  until grep -q "active=$expected_path" "$WORK_DIR/client.log"; do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
      sed -n '1,160p' "$WORK_DIR/client.log" >&2
      exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 200 ]; then
      sed -n '1,160p' "$WORK_DIR/client.log" >&2
      echo "carrier client readiness timeout" >&2
      exit 1
    fi
    sleep 0.05
  done
  if ! response=$(
    python3 -c 'import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(3)
payload=("carrier-"+sys.argv[2]).encode()
s.sendto(payload,("127.0.0.1",int(sys.argv[1])))
reply,_=s.recvfrom(2048)
sys.stdout.write(reply.decode())' "$LOCAL_PORT" "$expected_path"
  ); then
    sed -n '1,200p' "$WORK_DIR/client.log" >&2
    sed -n '1,200p' "$WORK_DIR/server.log" >&2
    exit 1
  fi
  test "$response" = "carrier-$expected_path"
  kill "$CLIENT_PID"
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=""
}

run_client h3,h2 primary-h3
run_client h2,h3 primary-h2

"$BIN_DIR/winn-audit" \
  -audit-log "$WORK_DIR/carrier-audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" >/dev/null

echo "PASS: authenticated H3 and H2 carrier commands relayed fixed-backend UDP with one stable session/generation"
