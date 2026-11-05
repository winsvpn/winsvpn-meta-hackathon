#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
ADB=${ADB:-/Users/winsvpn/Library/Android/sdk/platform-tools/adb}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-protocol-android.XXXXXX")
PKI_DIR="$WORK_DIR/pki"
BIN_DIR="$WORK_DIR/bin"
REMOTE_DIR="/data/local/tmp/winn-protocol-smoke-$$"
SERVER_PID=""
PORT=${WINN_ANDROID_PORT:-19444}
CARRIER_PORT=${WINN_ANDROID_CARRIER_PORT:-19449}
CARRIER_METRICS_PORT=${WINN_ANDROID_CARRIER_METRICS_PORT:-19450}
CARRIER_BACKEND_PORT=${WINN_ANDROID_CARRIER_BACKEND_PORT:-19451}
CARRIER_LOCAL_PORT=${WINN_ANDROID_CARRIER_LOCAL_PORT:-19452}
CARRIER_SERVER_PID=""
CARRIER_ECHO_PID=""
CARRIER_CLIENT_PID=""
CARRIER_LAUNCH_PID=""
PEER_PUBLIC_KEY="<REDACTED_WG_KEY>"

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$CARRIER_SERVER_PID" ]; then
    kill "$CARRIER_SERVER_PID" 2>/dev/null || true
    wait "$CARRIER_SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$CARRIER_ECHO_PID" ]; then
    kill "$CARRIER_ECHO_PID" 2>/dev/null || true
    wait "$CARRIER_ECHO_PID" 2>/dev/null || true
  fi
  if [ -n "$CARRIER_CLIENT_PID" ]; then
    "$ADB" shell "kill '$CARRIER_CLIENT_PID'" >/dev/null 2>&1 || true
  fi
  if [ -n "$CARRIER_LAUNCH_PID" ]; then
    kill "$CARRIER_LAUNCH_PID" 2>/dev/null || true
    wait "$CARRIER_LAUNCH_PID" 2>/dev/null || true
  fi
  "$ADB" reverse --remove "tcp:$PORT" >/dev/null 2>&1 || true
  "$ADB" reverse --remove "tcp:$CARRIER_PORT" >/dev/null 2>&1 || true
  "$ADB" shell "rm -r '$REMOTE_DIR'" >/dev/null 2>&1 || true
  rm -r "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$ADB" ]; then
  echo "adb not executable: $ADB" >&2
  exit 1
fi
if ! "$ADB" get-state 2>/dev/null | grep -q '^device$'; then
  echo "no authorized Android device connected" >&2
  exit 1
fi
abi=$("$ADB" shell getprop ro.product.cpu.abi | tr -d '\r')
case "$abi" in
  arm64-v8a) ;;
  *)
    echo "connected device ABI $abi is not arm64-v8a" >&2
    exit 1
    ;;
esac

mkdir -p "$BIN_DIR"
cd "$ROOT_DIR"
"$GO_BIN" build -o "$BIN_DIR/winn-pki" ./cmd/winn-pki
"$GO_BIN" build -o "$BIN_DIR/winn-server" ./cmd/winn-server
"$GO_BIN" build -o "$BIN_DIR/winn-carrier-server" ./cmd/winn-carrier-server
"$GO_BIN" build -o "$BIN_DIR/winn-audit" ./cmd/winn-audit
CGO_ENABLED=0 GOOS=android GOARCH=arm64 "$GO_BIN" build -o "$BIN_DIR/winn-client-android-arm64" ./cmd/winn-client
CGO_ENABLED=0 GOOS=android GOARCH=arm64 "$GO_BIN" build -o "$BIN_DIR/winn-carrier-client-android-arm64" ./cmd/winn-carrier-client
"$BIN_DIR/winn-pki" -out "$PKI_DIR" -server-name localhost -device-id android-usb-1 >/dev/null

"$ADB" shell "mkdir -p '$REMOTE_DIR' && chmod 700 '$REMOTE_DIR'"
"$ADB" push "$BIN_DIR/winn-client-android-arm64" "$REMOTE_DIR/winn-client" >/dev/null
"$ADB" push "$BIN_DIR/winn-carrier-client-android-arm64" "$REMOTE_DIR/winn-carrier-client" >/dev/null
"$ADB" push "$PKI_DIR/ca.pem" "$REMOTE_DIR/ca.pem" >/dev/null
"$ADB" push "$PKI_DIR/device.pem" "$REMOTE_DIR/device.pem" >/dev/null
"$ADB" push "$PKI_DIR/device-key.pem" "$REMOTE_DIR/device-key.pem" >/dev/null
"$ADB" push "$PKI_DIR/device-mldsa65.seed" "$REMOTE_DIR/device-mldsa65.seed" >/dev/null
"$ADB" push "$PKI_DIR/device-mldsa87.seed" "$REMOTE_DIR/device-mldsa87.seed" >/dev/null
"$ADB" push "$PKI_DIR/controller-mldsa65.pub" "$REMOTE_DIR/controller-mldsa65.pub" >/dev/null
"$ADB" push "$PKI_DIR/controller-mldsa87.pub" "$REMOTE_DIR/controller-mldsa87.pub" >/dev/null
"$ADB" push "$PKI_DIR/controller-pq-pins.json" "$REMOTE_DIR/controller-pq-pins.json" >/dev/null
"$ADB" push "$PKI_DIR/ech-config-list.bin" "$REMOTE_DIR/ech-config-list.bin" >/dev/null
"$ADB" shell "chmod 700 '$REMOTE_DIR/winn-client' '$REMOTE_DIR/winn-carrier-client'; chmod 600 '$REMOTE_DIR'/*.pem '$REMOTE_DIR'/*.seed '$REMOTE_DIR'/*.pub '$REMOTE_DIR'/*.json"
"$ADB" shell "chmod 600 '$REMOTE_DIR/ech-config-list.bin'"
"$ADB" reverse "tcp:$PORT" "tcp:$PORT" >/dev/null

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
      DEVICE_PQ_SEED="$REMOTE_DIR/device-mldsa87.seed"
      CONTROLLER_PQ_PUBLIC="$REMOTE_DIR/controller-mldsa87.pub"
      ;;
    *)
      CONTROLLER_PQ_SEED="$PKI_DIR/controller-mldsa65.seed"
      DEVICE_PQ_SEED="$REMOTE_DIR/device-mldsa65.seed"
      CONTROLLER_PQ_PUBLIC="$REMOTE_DIR/controller-mldsa65.pub"
      ;;
  esac
}

generation=0
for suite in x25519-mlkem768 p256-mlkem768 p384-mlkem1024; do
  select_pq_paths "$suite"
  start_server "$suite"
  android_output=$(
    "$ADB" shell \
      "'$REMOTE_DIR/winn-client' -endpoint 'https://localhost:$PORT' -cert '$REMOTE_DIR/device.pem' -key '$REMOTE_DIR/device-key.pem' -ca '$REMOTE_DIR/ca.pem' -server-name localhost -controller-id winn-controller-1 -device-id android-usb-1 -peer-public-key '$PEER_PUBLIC_KEY' -state '$REMOTE_DIR/client.state' -device-pq-seed '$DEVICE_PQ_SEED' -controller-pq-public '$CONTROLLER_PQ_PUBLIC' -suite '$suite' -ech-config-list '$REMOTE_DIR/ech-config-list.bin' -apply-file '$REMOTE_DIR/client.psk' -lab-mode" |
      tr -d '\r'
  )
  wait "$SERVER_PID"
  SERVER_PID=""
  generation=$((generation + 1))
  echo "$android_output" | grep -q '"status":"applied"'
  echo "$android_output" | grep -q "\"generation\":$generation"
  echo "$android_output" | grep -q "\"suite\":\"$suite\""
  "$ADB" pull "$REMOTE_DIR/client.psk" "$WORK_DIR/android-client.psk" >/dev/null
  cmp "$WORK_DIR/server.psk" "$WORK_DIR/android-client.psk"
done

python3 -c 'import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("127.0.0.1",int(sys.argv[1])))
while True:
 data,peer=s.recvfrom(2048)
 s.sendto(data,peer)' "$CARRIER_BACKEND_PORT" >"$WORK_DIR/carrier-echo.log" 2>&1 &
CARRIER_ECHO_PID=$!

"$BIN_DIR/winn-carrier-server" \
  -addr "127.0.0.1:$CARRIER_PORT" \
  -metrics-addr "127.0.0.1:$CARRIER_METRICS_PORT" \
  -masque-template "https://localhost:$CARRIER_PORT/.well-known/masque/udp/{target_host}/{target_port}/" \
  -public-target winn.invalid:443 \
  -awg-backend "127.0.0.1:$CARRIER_BACKEND_PORT" \
  -cert "$PKI_DIR/server.pem" \
  -key "$PKI_DIR/server-key.pem" \
  -client-ca "$PKI_DIR/ca.pem" \
  -device-registry "$PKI_DIR/device-pq-registry.json" \
  -controller-pq-seed "$PKI_DIR/controller-mldsa65.seed" \
  -controller-pq-algorithm mldsa65 \
  -controller-id winn-controller-1 \
  -suite x25519-mlkem768 \
  -ech-keys "$PKI_DIR/ech-server-keys.json" \
  -audit-log "$WORK_DIR/carrier-audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" \
  -lab-mode \
  -insecure-cover-reuses-winn-leaf >"$WORK_DIR/carrier-server.log" 2>&1 &
CARRIER_SERVER_PID=$!

attempts=0
until curl --fail --silent "http://127.0.0.1:$CARRIER_METRICS_PORT/readyz" >/dev/null 2>&1; do
  if ! kill -0 "$CARRIER_SERVER_PID" 2>/dev/null; then
    sed -n '1,160p' "$WORK_DIR/carrier-server.log" >&2
    exit 1
  fi
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 100 ]; then
    echo "carrier server readiness timeout" >&2
    exit 1
  fi
  sleep 0.05
done
"$ADB" reverse "tcp:$CARRIER_PORT" "tcp:$CARRIER_PORT" >/dev/null

"$ADB" shell \
  "cd '$REMOTE_DIR' && setsid -d ./winn-carrier-client \
      -masque-template 'https://localhost:$CARRIER_PORT/.well-known/masque/udp/{target_host}/{target_port}/' \
      -h2-url 'https://localhost:$CARRIER_PORT/winn/v2/udp-stream' \
      -public-target 'winn.invalid:443' \
      -local '127.0.0.1:$CARRIER_LOCAL_PORT' \
      -metrics-addr '' \
      -cert '$REMOTE_DIR/device.pem' \
      -key '$REMOTE_DIR/device-key.pem' \
      -root-ca '$REMOTE_DIR/ca.pem' \
      -server-name localhost \
      -device-id android-usb-1 \
      -device-pq-seed '$REMOTE_DIR/device-mldsa65.seed' \
      -controller-pq-pins '$REMOTE_DIR/controller-pq-pins.json' \
      -controller-id winn-controller-1 \
      -suite x25519-mlkem768 \
      -ech-config-list '$REMOTE_DIR/ech-config-list.bin' \
      -session-id 0123456789abcdef0123456789abcdef \
      -tunnel-generation 4 \
      -carriers h2,h3 \
      -lab-mode >'$REMOTE_DIR/carrier.log' 2>&1 </dev/null" >/dev/null 2>&1 &
CARRIER_LAUNCH_PID=$!
attempts=0
while [ -z "$CARRIER_CLIENT_PID" ]; do
  CARRIER_CLIENT_PID=$("$ADB" shell "pidof winn-carrier-client" 2>/dev/null | tr -d '\r')
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 100 ]; then
    echo "Android carrier client did not start" >&2
    exit 1
  fi
  sleep 0.05
done
case "$CARRIER_CLIENT_PID" in
  *[!0-9]*|"")
    echo "invalid Android carrier client PID: $CARRIER_CLIENT_PID" >&2
    exit 1
    ;;
esac
attempts=0
until "$ADB" shell "grep -q 'active=primary-h2' '$REMOTE_DIR/carrier.log'" >/dev/null 2>&1; do
  if ! "$ADB" shell "kill -0 '$CARRIER_CLIENT_PID'" >/dev/null 2>&1; then
    "$ADB" shell "cat '$REMOTE_DIR/carrier.log'" >&2 || true
    exit 1
  fi
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 200 ]; then
    "$ADB" shell "cat '$REMOTE_DIR/carrier.log'" >&2 || true
    echo "Android carrier client readiness timeout" >&2
    exit 1
  fi
  sleep 0.05
done
carrier_echo=$(
  "$ADB" shell \
    "printf 'android-h2-carrier-echo' | toybox nc -4 -n -u -p '$((CARRIER_LOCAL_PORT + 1))' -q 2 -W 3 -w 3 127.0.0.1 '$CARRIER_LOCAL_PORT'" |
    tr -d '\r'
)
test "$carrier_echo" = "android-h2-carrier-echo"
"$ADB" shell "kill '$CARRIER_CLIENT_PID'" >/dev/null 2>&1 || true
CARRIER_CLIENT_PID=""
wait "$CARRIER_LAUNCH_PID" 2>/dev/null || true
CARRIER_LAUNCH_PID=""
kill "$CARRIER_SERVER_PID"
wait "$CARRIER_SERVER_PID" 2>/dev/null || true
CARRIER_SERVER_PID=""
"$BIN_DIR/winn-audit" \
  -audit-log "$WORK_DIR/carrier-audit.jsonl" \
  -audit-key "$PKI_DIR/audit.key" >/dev/null

model=$("$ADB" shell getprop ro.product.model | tr -d '\r')
echo "PASS: Android $model negotiated all 3 hybrid suites, matched controller PSKs, and relayed authenticated H2 fallback UDP with a stable Winn session"
