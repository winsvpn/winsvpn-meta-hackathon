#!/bin/sh
# -tun-gso harness: runs TestTunGSOHarness (forward_gso_harness_linux_test.go)
# against a real Linux kernel, inside two throwaway network namespaces. Needs
# root, iproute2 and ethtool; no node, no network access, no gateway service.
#
# Build the test binary for the host's architecture, then run this as root:
#   GOOS=linux GOARCH=arm64 go test -c -o winn3-gateway-gso.test ./cmd/winn3-gateway
#   sudo sh cmd/winn3-gateway/testdata/tun_gso_harness.sh ./winn3-gateway-gso.test
#
# Layout:  [wgso-gw]  wgso0 10.77.0.1/24 (the TUN, client 10.77.0.7)
#                     veth wgso-g 10.78.0.1/24, TSO, GSO and tx checksum OFF
#          [wgso-far] veth wgso-f 10.78.0.2/24, listener on :5201
# With offloads off on the gateway's veth, the kernel segments every GSO
# super packet in software and computes each checksum itself, and the far
# side verifies them, so a defect in buildGSO shows up as a drop.
set -eu
BIN=${1:?usage: tun_gso_harness.sh /path/to/winn3-gateway.test}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for c in ip ethtool; do
	command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 2; }
done
cleanup() {
	ip netns del wgso-gw 2>/dev/null || true
	ip netns del wgso-far 2>/dev/null || true
}
trap cleanup EXIT
cleanup
ip netns add wgso-gw
ip netns add wgso-far
ip link add wgso-g type veth peer name wgso-f
ip link set wgso-g netns wgso-gw
ip link set wgso-f netns wgso-far
ip -n wgso-gw addr add 10.78.0.1/24 dev wgso-g
ip -n wgso-far addr add 10.78.0.2/24 dev wgso-f
ip -n wgso-gw link set lo up
ip -n wgso-far link set lo up
ip -n wgso-gw link set wgso-g up
ip -n wgso-far link set wgso-f up
ip netns exec wgso-gw ethtool -K wgso-g tso off gso off tx off >/dev/null
ip netns exec wgso-far ethtool -K wgso-f tx off >/dev/null
ip netns exec wgso-gw sysctl -qw net.ipv4.ip_forward=1
ip netns exec wgso-gw sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec wgso-gw sysctl -qw net.ipv4.conf.default.rp_filter=0
ip -n wgso-far route add 10.77.0.0/24 via 10.78.0.1
ip netns exec wgso-gw env WINN_TUN_GSO_HARNESS=1 WINN_TUN_GSO_FAR_NS=wgso-far \
	"$BIN" -test.run '^TestTunGSOHarness$' -test.count=1 -test.v
