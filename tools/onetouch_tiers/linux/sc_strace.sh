#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Scenario STRACE-fd9-trace: the deterministic fd 9 trace of rotate-serving (design v17 5.5, v11 fix 5, v12 fix 7, v13).
# tier_a.py runs it only on a guest where `strace` is installed (scenarios.py `needs`); without it the scenario is
# reported blocked, never passed. The judgement is s7_fd9_trace.py, tested on the Mac with canned traces.

sc_strace_fd9_trace() {
  command -v strace >/dev/null 2>&1 || { fx_skip "strace is not installed on this guest (owner decision D8)"; return 0; }
  fx_state chain-open
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\n# changed installer bytes\n' > "${FX_T}/installer2.sh"
  local sha2 root
  sha2="$(sha256sum "${FX_T}/installer2.sh" | cut -d' ' -f1)"
  # the rotation holds the lock for about 2 s (sync_path calls `sync` twice), so the contender below is really waiting
  cat > "${FX_T}/stubs/sync" <<'STUB'
#!/bin/bash
[[ -e "${FX_STATE}/slow-sync" ]] && sleep 1
exec /usr/bin/sync "$@"
STUB
  chmod +x "${FX_T}/stubs/sync"
  : > "${FX_STATE}/slow-sync"
  (
    WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer2.sh" \
      strace -f -o "${FX_STATE}/fd9.trace" -e trace=openat,dup2,dup3,close,close_range,fcntl,flock \
      bash -c 'echo "$$" > "$1"; exec "$2" rotate-serving --installer-sha256 "$3"' _ \
      "${FX_STATE}/root.pid" /usr/local/sbin/wins-node-local-serving "${sha2}" >"${FX_STATE}/rot.out" 2>&1
    echo "$?" > "${FX_STATE}/rot.rc"
    date +%s.%N > "${FX_STATE}/rot.end"
  ) &
  local rot=$!
  sleep 1.2
  (
    # a second non-status command, blocked on fd 9 while rotate-serving holds it
    WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer2.sh" WINS_NODE_LOCAL_SERVING_LOCK_WAIT=20 \
      fx_guard rotate-serving --installer-sha256 "${sha2}" >"${FX_STATE}/contender.out" 2>&1
    echo "$?" > "${FX_STATE}/contender.rc"
    date +%s.%N > "${FX_STATE}/contender.end"
  ) &
  local con=$!
  wait "${rot}" "${con}"
  rm -f "${FX_STATE}/slow-sync"
  fx_eq "rotate-serving under strace exits 0" 0 "$(cat "${FX_STATE}/rot.rc")"
  grep -q 'latch rotated' "${FX_STATE}/rot.out" && fx_ok "rotate-serving rotated the latch under strace" || fx_fail "no rotation: $(head -c 200 "${FX_STATE}/rot.out")"
  fx_eq "the contender completed with no fd 7 or fd 9 timeout" 0 "$(cat "${FX_STATE}/contender.rc")"
  python3 - "${FX_STATE}/rot.end" "${FX_STATE}/contender.end" <<'PY' && fx_ok "the contender finished only after rotate-serving exited" || fx_fail "the contender overtook rotate-serving"
import sys
rot, con = (float(open(p).read()) for p in sys.argv[1:3])
sys.exit(0 if con >= rot - 0.01 else 1)
PY
  root="$(cat "${FX_STATE}/root.pid" 2>/dev/null)"
  fx_note "trace lines: $(wc -l < "${FX_STATE}/fd9.trace" 2>/dev/null) root pid ${root}"
  if python3 "${FX_BUNDLE}/s7_fd9_trace.py" "${FX_STATE}/fd9.trace" "${root}" /run/lock/wins-node-local-serving.lock >"${FX_STATE}/verdict.json" 2>&1; then
    fx_ok "the fd 9 trace holds: one acquisition before the boundary, none after, no fd 9 change in the guard's shell"
  else
    fx_fail "fd 9 trace: $(head -c 300 "${FX_STATE}/verdict.json")"
  fi
}
