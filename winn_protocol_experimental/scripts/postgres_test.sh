#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
DOCKER_BIN=${DOCKER_BIN:-docker}
. "$ROOT_DIR/scripts/postgres_container_cleanup.sh"
# shellcheck source=scripts/postgres_cleanup_traps.sh
. "$ROOT_DIR/scripts/postgres_cleanup_traps.sh"
CONTAINER_NAME="winn-postgres-test-$$"
CONTAINER_ID=""
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-postgres-smoke.XXXXXX")
SERVER_PID=""
PROTOCOL_PORT=${WINN_POSTGRES_SMOKE_PORT:-19445}
PEER_PUBLIC_KEY="<REDACTED_WG_KEY>"
umask 077

postgres_cleanup_resources() {
  cleanup_failed=0
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$CONTAINER_ID" ]; then
    if ! winn_postgres_stop_remove_container "$DOCKER_BIN" "$CONTAINER_ID"; then
      cleanup_failed=1
    fi
  fi
  if ! rm -r "$WORK_DIR"; then
    cleanup_failed=1
  fi
  return "$cleanup_failed"
}
winn_postgres_install_cleanup_traps postgres_cleanup_resources

sh "$ROOT_DIR/scripts/test_postgres_container_cleanup.sh"

CONTAINER_ID=$(
  "$DOCKER_BIN" run --rm -d \
    --name "$CONTAINER_NAME" \
    -e POSTGRES_USER=winn_test \
    -e POSTGRES_PASSWORD=winn_test_password \
    -e POSTGRES_DB=winn_test \
    -p 127.0.0.1::5432 \
    postgres:18-alpine
)

attempt=0
until "$DOCKER_BIN" exec "$CONTAINER_ID" \
  psql -U winn_test -d winn_test -c 'SELECT 1' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 120 ]; then
    "$DOCKER_BIN" logs "$CONTAINER_ID" >&2
    exit 1
  fi
  sleep 0.25
done

HOST_PORT=$("$DOCKER_BIN" port "$CONTAINER_ID" 5432/tcp | awk -F: 'NR == 1 {print $NF}')
if [ -z "$HOST_PORT" ]; then
  echo "could not resolve disposable PostgreSQL port" >&2
  exit 1
fi

cd "$ROOT_DIR"
"$DOCKER_BIN" exec -i "$CONTAINER_ID" \
  psql -v ON_ERROR_STOP=1 -U winn_test -d winn_test \
  <schema/postgres_v1.sql >/dev/null
WINN_POSTGRES_TEST_DSN="postgres://winn_test:winn_test_password@127.0.0.1:$HOST_PORT/winn_test?sslmode=disable" \
  "$GO_BIN" test ./internal/state -run 'Postgres' -count=1

mkdir -p "$WORK_DIR/bin"
"$GO_BIN" build -o "$WORK_DIR/bin/winn-pki" ./cmd/winn-pki
"$GO_BIN" build -o "$WORK_DIR/bin/winn-server" ./cmd/winn-server
"$GO_BIN" build -o "$WORK_DIR/bin/winn-client" ./cmd/winn-client
"$WORK_DIR/bin/winn-pki" \
  -out "$WORK_DIR/pki" \
  -server-name localhost \
  -device-id postgres-smoke-1 >/dev/null
printf '%s\n' \
  "postgres://winn_test:winn_test_password@127.0.0.1:$HOST_PORT/winn_test?sslmode=disable" \
  >"$WORK_DIR/postgres.dsn"

"$WORK_DIR/bin/winn-server" \
  -listen "127.0.0.1:$PROTOCOL_PORT" \
  -admin-listen "127.0.0.1:0" \
  -cert "$WORK_DIR/pki/server.pem" \
  -key "$WORK_DIR/pki/server-key.pem" \
  -client-ca "$WORK_DIR/pki/ca.pem" \
  -postgres-dsn-file "$WORK_DIR/postgres.dsn" \
  -postgres-insecure-loopback \
  -state-key "$WORK_DIR/pki/state.key" \
  -audit-log "$WORK_DIR/audit.jsonl" \
  -audit-key "$WORK_DIR/pki/audit.key" \
  -controller-id winn-controller-1 \
  -controller-pq-seed "$WORK_DIR/pki/controller-mldsa65.seed" \
  -device-pq-registry "$WORK_DIR/pki/device-pq-registry.json" \
  -suite x25519-mlkem768 \
  -ech-keys "$WORK_DIR/pki/ech-server-keys.json" \
  -apply-file "$WORK_DIR/server.psk" \
  -lab-mode \
  -insecure-cover-reuses-winn-leaf \
  -once >"$WORK_DIR/server.log" 2>&1 &
SERVER_PID=$!

attempt=0
while ! grep -q '"event":"ready"' "$WORK_DIR/server.log"; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    sed -n '1,120p' "$WORK_DIR/server.log" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo "PostgreSQL server smoke readiness timeout" >&2
    exit 1
  fi
  sleep 0.05
done

"$WORK_DIR/bin/winn-client" \
  -endpoint "https://localhost:$PROTOCOL_PORT" \
  -cert "$WORK_DIR/pki/device.pem" \
  -key "$WORK_DIR/pki/device-key.pem" \
  -ca "$WORK_DIR/pki/ca.pem" \
  -server-name localhost \
  -device-id postgres-smoke-1 \
  -peer-public-key "$PEER_PUBLIC_KEY" \
  -state "$WORK_DIR/client.state" \
  -controller-id winn-controller-1 \
  -device-pq-seed "$WORK_DIR/pki/device-mldsa65.seed" \
  -controller-pq-pins "$WORK_DIR/pki/controller-pq-pins.json" \
  -suite x25519-mlkem768 \
  -ech-config-list "$WORK_DIR/pki/ech-config-list.bin" \
  -apply-file "$WORK_DIR/client.psk" \
  -lab-mode >/dev/null
wait "$SERVER_PID"
SERVER_PID=""
cmp "$WORK_DIR/server.psk" "$WORK_DIR/client.psk"

if ! winn_postgres_stop_remove_container "$DOCKER_BIN" "$CONTAINER_ID"; then
  echo "disposable PostgreSQL cleanup could not be proven" >&2
  exit 1
fi
CONTAINER_ID=""

echo "PASS: PostgreSQL schema, transactional store tests, controller CLI, pin set, and PSK agreement"
