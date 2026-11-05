#!/bin/bash
# An iptables stand-in for the predicate fixtures: when the argument string matches W_RE it
# prints W_OUT on stdout and W_MSG on stderr and exits W_RC; otherwise it runs the real iptables.
if [[ -n "${W_RE:-}" && "$*" =~ ${W_RE} ]]; then
  [[ -z "${W_OUT:-}" ]] || printf '%s\n' "${W_OUT}"
  [[ -z "${W_MSG:-}" ]] || printf '%s\n' "${W_MSG}" >&2
  exit "${W_RC:-1}"
fi
exec /usr/sbin/iptables "$@"
