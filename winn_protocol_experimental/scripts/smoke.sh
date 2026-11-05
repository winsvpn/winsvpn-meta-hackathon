#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-protocol-smoke.XXXXXX")
BIN_DIR="$WORK_DIR/bin"
PKI_DIR="$WORK_DIR/pki"
SERVER_PID=""
PORT=${WINN_SMOKE_PORT:-19443}
PEER_PUBLIC_KEY="<REDACTED_WG_KEY>"

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -r "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$BIN_DIR"
cd "$ROOT_DIR"
"$GO_BIN" build -o "$BIN_DIR/winn-pki" ./cmd/winn-pki
"$GO_BIN" build -o "$BIN_DIR/winn-server" ./cmd/winn-server
"$GO_BIN" build -o "$BIN_DIR/winn-client" ./cmd/winn-client
"$GO_BIN" build -o "$BIN_DIR/winn-admin" ./cmd/winn-admin
"$GO_BIN" build -o "$BIN_DIR/winn-audit" ./cmd/winn-audit
"$BIN_DIR/winn-pki" -out "$PKI_DIR" -server-name localhost -device-id smoke-device-1 >/dev/null

start_server() {
  suite=$1
  select_pq_paths "$suite"
  : >"$WORK_DIR/server.log"
  "$BIN_DIR/winn-server" \
    -listen "127.0.0.1:$PORT" \
    -admin-listen "127.0.0.1:0" \
    -cert "$PKI_DIR/server.pem" \
    -key "$PKI_DIR/server-key.pem" \
    -client-ca "$PKI_DIR/ca.pem" \
    -state "$WORK_DIR/controller.state" \
    -state-key "$PKI_DIR/state.key" \
    -audit-log "$WORK_DIR/audit.jsonl" \
    -audit-key "$PKI_DIR/audit.key" \
    -controller-id winn-controller-1 \
    -controller-pq-seed "$CONTROLLER_PQ_SEED" \
    -device-pq-registry "$PKI_DIR/device-pq-registry.json" \
    -suite "$suite" \
    -ech-keys "$PKI_DIR/ech-server-keys.json" \
    -apply-file "$WORK_DIR/server.psk" \
    -lab-mode \
    -insecure-cover-reuses-winn-leaf \
    -once >"$WORK_DIR/server.log" 2>&1 &
  SERVER_PID=$!
  attempts=0
  while ! grep -q '"event":"ready"' "$WORK_DIR/server.log"; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      sed -n '1,120p' "$WORK_DIR/server.log" >&2
      return 1
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 100 ]; then
      echo "server readiness timeout" >&2
      return 1
    fi
    sleep 0.05
  done
}

select_pq_paths() {
  suite=$1
  case "$suite" in
    p384-mlkem1024)
      CONTROLLER_PQ_SEED="$PKI_DIR/controller-mldsa87.seed"
      CONTROLLER_PQ_PUBLIC="$PKI_DIR/controller-mldsa87.pub"
      DEVICE_PQ_SEED="$PKI_DIR/device-mldsa87.seed"
      ;;
    *)
      CONTROLLER_PQ_SEED="$PKI_DIR/controller-mldsa65.seed"
      CONTROLLER_PQ_PUBLIC="$PKI_DIR/controller-mldsa65.pub"
      DEVICE_PQ_SEED="$PKI_DIR/device-mldsa65.seed"
      ;;
  esac
}

previous_psk="$WORK_DIR/previous.psk"
generation=0
for suite in x25519-mlkem768 p256-mlkem768 p384-mlkem1024; do
  select_pq_paths "$suite"
  start_server "$suite"
  client_output=$(
    "$BIN_DIR/winn-client" \
      -endpoint "https://localhost:$PORT" \
      -cert "$PKI_DIR/device.pem" \
      -key "$PKI_DIR/device-key.pem" \
      -ca "$PKI_DIR/ca.pem" \
      -server-name localhost \
      -device-id smoke-device-1 \
      -peer-public-key "$PEER_PUBLIC_KEY" \
      -state "$WORK_DIR/client.state" \
      -controller-id winn-controller-1 \
      -device-pq-seed "$DEVICE_PQ_SEED" \
      -controller-pq-public "$CONTROLLER_PQ_PUBLIC" \
      -suite "$suite" \
      -ech-config-list "$PKI_DIR/ech-config-list.bin" \
      -apply-file "$WORK_DIR/client.psk" \
      -lab-mode
  )
  wait "$SERVER_PID"
  SERVER_PID=""
  generation=$((generation + 1))
  echo "$client_output" | grep -q '"status":"applied"'
  echo "$client_output" | grep -q "\"generation\":$generation"
  echo "$client_output" | grep -q "\"suite\":\"$suite\""
  cmp "$WORK_DIR/server.psk" "$WORK_DIR/client.psk"
  if [ -f "$previous_psk" ] && cmp -s "$previous_psk" "$WORK_DIR/client.psk"; then
    echo "PSK did not change between generations" >&2
    exit 1
  fi
  cp "$WORK_DIR/client.psk" "$previous_psk"
done

select_pq_paths p384-mlkem1024
"$BIN_DIR/winn-admin" \
  -state "$WORK_DIR/controller.state" \
  -state-key "$PKI_DIR/state.key" \
  -audit-log "$WORK_DIR/audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" \
  -controller-id winn-controller-1 \
  -action revoke \
  -device-id smoke-device-1 >/dev/null

start_server x25519-mlkem768
select_pq_paths x25519-mlkem768
if revoked_output=$(
  "$BIN_DIR/winn-client" \
    -endpoint "https://localhost:$PORT" \
    -cert "$PKI_DIR/device.pem" \
    -key "$PKI_DIR/device-key.pem" \
    -ca "$PKI_DIR/ca.pem" \
    -server-name localhost \
    -device-id smoke-device-1 \
    -peer-public-key "$PEER_PUBLIC_KEY" \
    -state "$WORK_DIR/client.state" \
    -controller-id winn-controller-1 \
    -device-pq-seed "$DEVICE_PQ_SEED" \
    -controller-pq-public "$CONTROLLER_PQ_PUBLIC" \
    -suite x25519-mlkem768 \
    -ech-config-list "$PKI_DIR/ech-config-list.bin" \
    -apply-file "$WORK_DIR/client.psk" \
    -lab-mode 2>&1
); then
  echo "revoked device unexpectedly rotated a key" >&2
  exit 1
fi
echo "$revoked_output" | grep -q 'device_revoked'
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

"$BIN_DIR/winn-audit" \
  -audit-log "$WORK_DIR/audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" >/dev/null

echo "PASS: 3 strict hybrid suites, matching controller/device PSKs, monotonic rotation, and revocation"
