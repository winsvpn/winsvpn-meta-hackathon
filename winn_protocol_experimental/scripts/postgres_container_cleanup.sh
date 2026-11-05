#!/bin/sh

# Stop an exact disposable PostgreSQL container and prove that Docker's
# --rm lifecycle removed it. A container name is deliberately not accepted:
# if the disposable container exits and its name is reused before cleanup,
# stopping by name could terminate an unrelated workload.
winn_postgres_container_state() {
  docker_bin=$1
  container_id=$2
  if ! listing=$(
    "$docker_bin" ps -aq --no-trunc --filter "id=$container_id"
  ); then
    echo "could not query disposable PostgreSQL container state" >&2
    return 2
  fi
  case "$listing" in
    "")
      return 1
      ;;
    "$container_id")
      return 0
      ;;
    *)
      echo "Docker returned an unexpected container identity: $listing" >&2
      return 2
      ;;
  esac
}

winn_postgres_stop_remove_container() {
  docker_bin=$1
  container_id=$2

  case "$container_id" in
    ""|*[!0-9a-f]*)
      echo "refusing invalid disposable PostgreSQL container ID" >&2
      return 1
      ;;
  esac
  if [ "${#container_id}" -ne 64 ]; then
    echo "refusing noncanonical disposable PostgreSQL container ID" >&2
    return 1
  fi

  if ! "$docker_bin" stop "$container_id" >/dev/null 2>&1; then
    if winn_postgres_container_state "$docker_bin" "$container_id"; then
      state=0
    else
      state=$?
    fi
    case "$state" in
      1)
        # It already exited and Docker --rm already removed the exact ID.
        return 0
        ;;
      0)
        echo "could not stop disposable PostgreSQL container $container_id" >&2
        return 1
        ;;
      *)
        return 1
        ;;
    esac
  fi

  attempts=${WINN_POSTGRES_CLEANUP_INSPECT_ATTEMPTS:-40}
  case "$attempts" in
    ""|*[!0-9]*|0)
      echo "invalid PostgreSQL cleanup inspection attempt count" >&2
      return 1
      ;;
  esac
  attempt=0
  while :; do
    if winn_postgres_container_state "$docker_bin" "$container_id"; then
      state=0
    else
      state=$?
    fi
    case "$state" in
      1)
        return 0
        ;;
      2)
        return 1
        ;;
      0)
        ;;
      *)
        echo "invalid disposable PostgreSQL container state" >&2
        return 1
        ;;
    esac
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$attempts" ]; then
      echo "disposable PostgreSQL container still exists after stop: $container_id" >&2
      return 1
    fi
    sleep 0.05
  done
}
