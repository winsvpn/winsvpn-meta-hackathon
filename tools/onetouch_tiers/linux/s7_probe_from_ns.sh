#!/usr/bin/env bash
# s7_probe_from_ns.sh PORT...   (Tier B, root, on the guest under test)
# Probes the node's own INPUT path from a throwaway client network namespace joined by a veth pair, with the
# same probe the Tier A fixtures use. Prints `tcp:<port>=answered|refused|silent udp:<port>=...`.
# "answered" = a service accepted or echoed; "refused" = the kernel replied with an RST or ICMP unreachable
# (no service answered); "silent" = dropped. Everything it creates is removed on exit.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
ns="s7probe$$"
cleanup() { ip netns del "${ns}" 2>/dev/null; ip link del s7v0 2>/dev/null; }
trap cleanup EXIT
ip netns add "${ns}" || exit 90
ip link add s7v0 type veth peer name s7v1 netns "${ns}" || exit 91
ip addr add 10.77.7.1/24 dev s7v0
ip link set s7v0 up
ip netns exec "${ns}" ip addr add 10.77.7.2/24 dev s7v1
ip netns exec "${ns}" ip link set s7v1 up
ip netns exec "${ns}" ip link set lo up
ip netns exec "${ns}" python3 "${here}/fx_probe.py" 10.77.7.1 "$@"
