#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Scenarios PRED-*: the dominance predicate (`wins_latch_rules_inspect`) against the guest's real iptables.

fx_pred_run() { # RULES_FILE MODE [IPTABLES_BIN]  -> rc, output in $FX_OUT
  FX_OUT="$(unshare -n bash -c '
    /usr/sbin/iptables-restore --wait 10 < "$1" || exit 99
    python3 "$2/dp/latch_predicate.py" "$4" "$3"' _ "$1" "${FX_BUNDLE}" "$2" "${3:-/usr/sbin/iptables}" 2>&1)"
  return $?
}

sc_pred_matrix() {
  local id expect mode rc
  while IFS=$'\t' read -r id expect mode _; do
    [[ -n "${id}" ]] || continue
    fx_pred_run "${FX_BUNDLE}/cases/${id}.rules" "${mode}"; rc=$?
    if [[ ${rc} == 99 ]]; then fx_fail "${id} :: ruleset did not load: ${FX_OUT}"; continue; fi
    if [[ "${expect}" == pass ]]; then
      if [[ ${rc} == 0 ]]; then fx_ok "${id}"; else fx_fail "${id} :: expected pass, rc=${rc}: ${FX_OUT}"; fi
    elif [[ ${rc} != 0 && "${FX_OUT}" == *"wins-latch: ${expect}:"* ]]; then
      fx_ok "${id} fails on ${expect}"
    else
      fx_fail "${id} :: expected ${expect}, rc=${rc}: ${FX_OUT}"
    fi
  done < "${FX_BUNDLE}/cases/index.tsv"
}

# Every relevant read error fails closed (5.3 fix 4 implementation rules).
sc_pred_read_errors() {
  local chain op rc re base="${FX_BUNDLE}/cases/pass-base-R-L.rules"
  for chain in INPUT WINVPN-SSH-RECOVERY WINVPN-LOCAL-SERVING; do
    for op in "-n -L" "-S"; do
      for rc in 1 2 4 127; do
        re="(^| )${op} ${chain}\$"
        FX_OUT="$(W_RE="${re}" W_RC="${rc}" W_MSG="injected read failure" unshare -n bash -c '
          /usr/sbin/iptables-restore --wait 10 < "$1" || exit 99
          python3 "$2/dp/latch_predicate.py" "$3" all' _ "${base}" "${FX_BUNDLE}" "${FX_BUNDLE}/fx_ipt_wrap.sh" 2>&1)"
        local got=$?
        if [[ ${got} != 0 && "${FX_OUT}" == *"wins-latch: inspection:"* ]]; then
          fx_ok "read error fails closed: ${op} ${chain} rc=${rc}"
        else
          fx_fail "read error not closed: ${op} ${chain} rc=${rc} got=${got}: ${FX_OUT}"
        fi
      done
    done
  done
}

# Absence of WINVPN-SSH-RECOVERY is read as absence only for exit status 1 plus iptables' own message.
sc_pred_absence() {
  local real_rc real_msg rc msg want got
  real_msg="$(unshare -n /usr/sbin/iptables -w 10 -n -L WINVPN-SSH-RECOVERY 2>&1)"; real_rc=$?
  fx_note "installed iptables, missing chain: rc=${real_rc} message=[${real_msg}] version=$(/usr/sbin/iptables --version)"
  fx_eq "installed iptables exits 1 for a missing chain" 1 "${real_rc}"
  [[ "${real_msg}" == *"No chain/target/match by that name"* ]] \
    && fx_ok "installed iptables prints the no-such-chain message the predicate matches" \
    || fx_fail "installed iptables message differs from the predicate's match string: [${real_msg}]"
  fx_pred_run "${FX_BUNDLE}/cases/pass-latch-only-base.rules" all; got=$?
  fx_eq "real absent recovery chain: predicate passes" 0 "${got}"
  while IFS=$'\t' read -r rc msg want; do
    [[ -n "${rc}" ]] || continue
    FX_OUT="$(W_RE='(^| )-n -L WINVPN-SSH-RECOVERY$' W_RC="${rc}" W_MSG="${msg}" unshare -n bash -c '
      /usr/sbin/iptables-restore --wait 10 < "$1" || exit 99
      python3 "$2/dp/latch_predicate.py" "$3" all' _ "${FX_BUNDLE}/cases/pass-latch-only-base.rules" "${FX_BUNDLE}" "${FX_BUNDLE}/fx_ipt_wrap.sh" 2>&1)"; got=$?
    if [[ "${want}" == pass ]]; then
      [[ ${got} == 0 ]] && fx_ok "absence accepted: rc=${rc} [${msg}]" || fx_fail "absence refused: rc=${rc} [${msg}]: ${FX_OUT}"
    else
      [[ ${got} != 0 ]] && fx_ok "not read as absence: rc=${rc} [${msg}]" || fx_fail "read as absence: rc=${rc} [${msg}]"
    fi
  done < "${FX_BUNDLE}/cases/absence.tsv"
}

# A line the parser cannot read, or a rule with no target, fails.
sc_pred_unparseable() {
  local text got
  for text in "garbage that is no rule" "-A INPUT -p tcp -m tcp --dport 22" "-A INPUT -j A -j B"; do
    FX_OUT="$(W_RE='(^| )-S INPUT$' W_RC=0 W_OUT="${text}" unshare -n bash -c '
      /usr/sbin/iptables-restore --wait 10 < "$1" || exit 99
      python3 "$2/dp/latch_predicate.py" "$3" all' _ "${FX_BUNDLE}/cases/pass-latch-only-base.rules" "${FX_BUNDLE}" "${FX_BUNDLE}/fx_ipt_wrap.sh" 2>&1)"; got=$?
    if [[ ${got} != 0 && "${FX_OUT}" == *"wins-latch: inspection:"* ]]; then fx_ok "unreadable INPUT line fails: [${text}]"
    else fx_fail "unreadable INPUT line accepted: [${text}] rc=${got} ${FX_OUT}"; fi
  done
}

# No side effects: creates no file, takes neither lock, returns while the locks are held,
# and issues only waited reads (5.3 "The gate itself").
sc_pred_no_side_effects() {
  fx_source_handler
  fx_load "${FX_BUNDLE}/cases/pass-base-R-L.rules"
  local before after rc
  rm -rf /run/lock/wins-node-local-serving.lock /run/lock/wins-firewall.lock
  rmdir /run/lock 2>/dev/null || true
  before="$(find /run /etc/winsvpn /var/lib/winsvpn /etc/iptables -xdev 2>/dev/null | sort | sha256sum)"
  : > "${FX_STATE}/ipt.log"
  wins_latch_rules_dominate; rc=$?
  after="$(find /run /etc/winsvpn /var/lib/winsvpn /etc/iptables -xdev 2>/dev/null | sort | sha256sum)"
  fx_eq "predicate passes on the base fixture" 0 "${rc}"
  fx_eq "predicate created no file or directory (lock dir and lock files absent before and after)" "${before}" "${after}"
  fx_refute "/run/lock/wins-node-local-serving.lock still absent" test -e /run/lock/wins-node-local-serving.lock
  fx_refute "/run/lock still absent" test -d /run/lock
  if grep -vE '^-w 10 (-n -L|-S) ' "${FX_STATE}/ipt.log" | grep -q .; then
    fx_fail "predicate issued a call other than a waited -S or -n -L read: $(grep -vE '^-w 10 (-n -L|-S) ' "${FX_STATE}/ipt.log" | head -3 | tr '\n' ';')"
  else
    fx_ok "predicate issued only waited -S and -n -L reads ($(wc -l < "${FX_STATE}/ipt.log") calls)"
  fi
  # Now with the locks held by other processes: it must return, not wait.
  mkdir -p /run/lock /var/lib/winsvpn/ssh-recovery; chmod 700 /var/lib/winsvpn/ssh-recovery
  : > /run/lock/wins-firewall.lock; : > /run/lock/wins-node-local-serving.lock; : > /var/lib/winsvpn/ssh-recovery/guard.lock
  local pids=() f
  for f in /run/lock/wins-firewall.lock /run/lock/wins-node-local-serving.lock /var/lib/winsvpn/ssh-recovery/guard.lock; do
    flock -x "${f}" sleep 30 & pids+=("$!")
  done
  sleep 0.3
  local started=$SECONDS
  timeout 8 bash -c "$(declare -f wins_latch_rules_inspect wins_latch_rules_dominate); wins_latch_rules_dominate"; rc=$?
  fx_eq "predicate returns 0 while fd 7 and both fd 9 lock files are held" 0 "${rc}"
  (( SECONDS - started < 6 )) && fx_ok "predicate returned promptly under held locks" || fx_fail "predicate waited under held locks"
  for f in "${pids[@]}"; do kill "${f}" 2>/dev/null; done
}
