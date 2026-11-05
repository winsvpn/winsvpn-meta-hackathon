#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=winn_leak_acceptance_v2_common.sh
. "$SCRIPT_DIR/winn_leak_acceptance_v2_common.sh"

hook_validate_context "$@"
hook_load_config

family_field() {
	hook_json_required ".families.$HOOK_FAMILY.$1"
}

UNDERLAY_INTERFACE=$(family_field underlay_interface)
GATEWAY_DNS_ENDPOINT=$(family_field gateway_dns_endpoint)
GATEWAY_DNS_ADDRESS=$(family_field gateway_dns_address)
GATEWAY_DNS_NONCE=$(family_field gateway_dns_nonce)
GATEWAY_DNS_ZONE=$(family_field gateway_dns_zone)
GATEWAY_DNS_ANSWER=$(family_field gateway_dns_answer)
GATEWAY_CANARY_ENDPOINT=$(family_field gateway_canary_endpoint)
OBSERVER_HTTP_ENDPOINT=$(family_field observer_http_endpoint)
OBSERVER_STUN_ENDPOINT=$(family_field observer_stun_endpoint)
OBSERVER_NONCE=$(family_field observer_nonce)
EXPECTED_GATEWAY_EGRESS=$(family_field expected_gateway_egress)
ORDINARY_DNS_ENDPOINT=$(family_field ordinary_dns_endpoint)
INNER_ADDRESSES=$(
	jq -ec --arg family "$HOOK_FAMILY" '
		.families[$family].inner_addresses |
		arrays | select(length > 0) |
		select(all(.[]; type == "string" and length > 0))
	' "$WINN_LEAK_HOOK_CONFIG"
) || hook_fail "family inner-address allowlist is invalid"

probe_output_dir() {
	printf '%s/client-%s\n' "$HOOK_EVIDENCE_DIR" "$HOOK_ACTION"
}

run_probe() {
	label=$1
	shift
	output=$(probe_output_dir)/$label.json
	[ ! -e "$output" ] || hook_fail "probe output already exists: $label"
	"$HOOK_NETPROBE" "$@" >"$output"
	chmod 0600 "$output"
	sync "$output"
}

assert_state_phase() {
	expected=$1
	actual=$(jq -er '.phase' "$(hook_state_path)")
	[ "$actual" = "$expected" ] ||
		hook_fail "client phase is $actual, expected $expected"
}

route_table_for_interface() {
	case "$HOOK_FAMILY" in
	v4) family_flag=-4 ;;
	v6) family_flag=-6 ;;
	esac
	tables=$(
		ip -j "$family_flag" route show table all |
			jq -r --arg interface "$HOOK_CLIENT_INTERFACE" '
				.[] |
				select(.dev == $interface) |
				(.table | tostring) |
				select(test("^[0-9]+$"))
			' |
			sort -u
	)
	[ "$(printf '%s\n' "$tables" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] ||
		hook_fail "client interface does not own exactly one route table"
	printf '%s' "$tables" | LC_ALL=C grep -Eq '^[1-9][0-9]{2,9}$' ||
		hook_fail "client route table ID is unsafe"
	printf '%s\n' "$tables"
}

assert_live_client_objects() {
	ip link show dev "$HOOK_CLIENT_INTERFACE" >/dev/null ||
		hook_fail "Winn interface is absent"
	ip -j address show dev "$HOOK_CLIENT_INTERFACE" |
		jq -e --argjson addresses "$INNER_ADDRESSES" '
			[
				.[].addr_info[]?.local |
				select(. as $candidate | $addresses | index($candidate) != null)
			] | length == 1
		' >/dev/null ||
		hook_fail "Winn interface omitted its permitted signed-pool address"
	nft list table inet "$HOOK_CLIENT_NFT_TABLE" >/dev/null ||
		hook_fail "Winn kill-switch table is absent"
}

assert_route_commit() {
	expect_commit=$1
	table=$(route_table_for_interface)
	case "$HOOK_FAMILY" in
	v4) family_flag=-4 ;;
	v6) family_flag=-6 ;;
	esac
	ip -j "$family_flag" route show table "$table" |
		jq -e --arg interface "$HOOK_CLIENT_INTERFACE" '
			any(.[]; .dev == $interface and .dst == "default")
		' >/dev/null ||
		hook_fail "Winn route table omitted the family default route"
	unmarked_count=$(
		ip -j "$family_flag" rule show |
			jq --arg table "$table" '
				[
					.[] |
					select((.table | tostring) == $table) |
					select((has("fwmark") | not))
				] | length
			'
	)
	case "$expect_commit" in
	yes)
		[ "$unmarked_count" -eq 1 ] ||
			hook_fail "committed route rule is absent or ambiguous"
		;;
	no)
		[ "$unmarked_count" -eq 0 ] ||
			hook_fail "default route was committed before the barrier"
		;;
	esac
}

assert_resolver_committed() {
	status=$(resolvectl status "$HOOK_CLIENT_INTERFACE")
	printf '%s\n' "$status" |
		grep -F "$GATEWAY_DNS_ADDRESS" >/dev/null ||
		hook_fail "resolver status omitted the tunnel DNS endpoint"
	printf '%s\n' "$status" | grep -F '~.' >/dev/null ||
		hook_fail "resolver status omitted the ~. routing domain"
}

assert_absent_client_objects() {
	if [ -n "${HOOK_CLIENT_INTERFACE:-}" ]; then
		ip link show dev "$HOOK_CLIENT_INTERFACE" >/dev/null 2>&1 &&
			hook_fail "Winn interface residue remains"
	fi
	if [ -n "${HOOK_CLIENT_NFT_TABLE:-}" ]; then
		nft list table inet "$HOOK_CLIENT_NFT_TABLE" >/dev/null 2>&1 &&
			hook_fail "Winn nftables table residue remains"
	fi
	return 0
}

blocked_probes() {
	run_probe http-blocked \
		-operation=http -expect=blocked -timeout=2s \
		-endpoint="$OBSERVER_HTTP_ENDPOINT" \
		-run-id="$HOOK_RUN_ID" -nonce="$OBSERVER_NONCE" \
		-expected-peer="$EXPECTED_GATEWAY_EGRESS" \
		-bind-interface="$UNDERLAY_INTERFACE"
	run_probe stun-blocked \
		-operation=stun -expect=blocked -timeout=2s \
		-endpoint="$OBSERVER_STUN_ENDPOINT" \
		-expected-peer="$EXPECTED_GATEWAY_EGRESS" \
		-bind-interface="$UNDERLAY_INTERFACE"
	case "$HOOK_FAMILY" in
	v4) ordinary_type=A; ordinary_answer=1.1.1.1 ;;
	v6) ordinary_type=AAAA; ordinary_answer=2606:4700:4700::1111 ;;
	esac
	run_probe dns-udp-blocked \
		-operation=dns-udp -expect=blocked -timeout=2s \
		-endpoint="$ORDINARY_DNS_ENDPOINT" -query=example.com. \
		-query-type="$ordinary_type" -expected-answer="$ordinary_answer" \
		-bind-interface="$UNDERLAY_INTERFACE"
	run_probe dns-tcp-blocked \
		-operation=dns-tcp -expect=blocked -timeout=2s \
		-endpoint="$ORDINARY_DNS_ENDPOINT" -query=example.com. \
		-query-type="$ordinary_type" -expected-answer="$ordinary_answer" \
		-bind-interface="$UNDERLAY_INTERFACE"
}

committed_probes() {
	case "$HOOK_FAMILY" in
	v4) query_type=A ;;
	v6) query_type=AAAA ;;
	esac
	run_probe dns-udp \
		-operation=dns-udp -expect=success -timeout=3s \
		-endpoint="$GATEWAY_DNS_ENDPOINT" \
		-query="$GATEWAY_DNS_NONCE.udp.$GATEWAY_DNS_ZONE." \
		-query-type="$query_type" -expected-answer="$GATEWAY_DNS_ANSWER"
	run_probe dns-tcp \
		-operation=dns-tcp -expect=success -timeout=3s \
		-endpoint="$GATEWAY_DNS_ENDPOINT" \
		-query="$GATEWAY_DNS_NONCE.tcp.$GATEWAY_DNS_ZONE." \
		-query-type="$query_type" -expected-answer="$GATEWAY_DNS_ANSWER"
	run_probe udp-canary \
		-operation=udp-echo -expect=success -timeout=3s \
		-endpoint="$GATEWAY_CANARY_ENDPOINT" \
		-payload="winn-leak-v2-$HOOK_RUN_ID-$HOOK_FAMILY"
	run_probe http \
		-operation=http -expect=success -timeout=3s \
		-endpoint="$OBSERVER_HTTP_ENDPOINT" \
		-run-id="$HOOK_RUN_ID" -nonce="$OBSERVER_NONCE" \
		-expected-peer="$EXPECTED_GATEWAY_EGRESS"
	run_probe stun \
		-operation=stun -expect=success -timeout=3s \
		-endpoint="$OBSERVER_STUN_ENDPOINT" \
		-expected-peer="$EXPECTED_GATEWAY_EGRESS"
}

case "$HOOK_ACTION" in
prepared)
	hook_load_client_state
	assert_state_phase prepared
	hook_control_plane_policy_admit
	hook_start_client_pcap
	hook_capture_client_state prepared
	assert_live_client_objects
	assert_route_commit no
	blocked_probes
	;;
verified)
	hook_load_client_state
	assert_state_phase verified
	hook_control_plane_policy_assert
	hook_capture_client_state verified
	assert_live_client_objects
	assert_route_commit no
	blocked_probes
	;;
committed)
	hook_load_client_state
	assert_state_phase committed
	hook_control_plane_policy_assert
	hook_capture_client_state committed
	assert_live_client_objects
	assert_route_commit yes
	assert_resolver_committed
	committed_probes
	;;
outage-fail-closed)
	hook_load_client_state
	assert_state_phase committed
	hook_control_plane_policy_assert
	hook_capture_client_state outage-fail-closed
	assert_live_client_objects
	assert_route_commit yes
	blocked_probes
	;;
recovered)
	hook_load_client_state
	assert_state_phase committed
	hook_control_plane_policy_assert
	hook_capture_client_state recovered
	assert_live_client_objects
	assert_route_commit yes
	assert_resolver_committed
	committed_probes
	;;
crashed-fail-closed)
	hook_load_client_state
	assert_state_phase crashing
	hook_control_plane_policy_assert
	hook_capture_client_state crashed-fail-closed
	assert_live_client_objects
	assert_route_commit yes
	blocked_probes
	;;
stopped)
	hook_load_client_state
	assert_state_phase stopped
	hook_capture_client_state stopped
	assert_absent_client_objects
	hook_stop_client_pcap
	;;
residue)
	if [ -f "$(hook_state_path)" ]; then
		hook_load_client_state
	fi
	hook_stop_client_pcap
	assert_absent_client_objects
	[ ! -e "$(hook_probe_runtime_path)" ] ||
		hook_fail "client pcap runtime residue remains"
	find "$HOOK_EVIDENCE_DIR/temp" -mindepth 1 -print -quit |
		grep . >/dev/null &&
		hook_fail "temporary client credential residue remains"
	echo "CLEAN role=probe run_id=$HOOK_RUN_ID family=$HOOK_FAMILY"
	;;
*) hook_fail "unsupported probe action: $HOOK_ACTION" ;;
esac
