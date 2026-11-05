#!/bin/sh
set -eu

# Build, temporarily deploy, smoke, remove, or run the Winn leak acceptance v2
# harness. Provider deployment is deliberately fixture-only. The six-case
# acceptance run is refused unless invoked on the marked disposable client.

ACTION=${1:-}
CONFIG_PATH=${2:-}
ARG3=${3:-}
ARG4=${4:-}
ARG5=${5:-}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)

fail() {
	echo "winn leak deployment v2: $*" >&2
	exit 1
}

json_required() {
	value=$(jq -er "$1 | strings | select(length > 0)" "$CONFIG_PATH") ||
		fail "missing deployment config field: $1"
	printf '%s\n' "$value"
}

validate_config() {
	[ -f "$CONFIG_PATH" ] && [ ! -L "$CONFIG_PATH" ] ||
		fail "deployment config must be a regular non-symlink file"
	case "$(uname -s)" in
	Darwin) config_mode=$(stat -f '%Lp' "$CONFIG_PATH") ;;
	*) config_mode=$(stat -c '%a' "$CONFIG_PATH") ;;
	esac
	[ "$config_mode" = 600 ] ||
		fail "deployment config mode must be 0600"
	[ "$(jq -er '.version' "$CONFIG_PATH")" = winn-leak-deployment-config/v2 ] ||
		fail "deployment config version mismatch"
	SSH_IDENTITY=$(json_required '.ssh.identity_file')
	SSH_FINGERPRINT=$(json_required '.ssh.public_fingerprint')
	KNOWN_HOSTS=$(json_required '.ssh.known_hosts_file')
	for path in "$SSH_IDENTITY" "$KNOWN_HOSTS"; do
		[ "${path#/}" != "$path" ] && [ -f "$path" ] && [ ! -L "$path" ] ||
			fail "SSH path must be an absolute regular file"
	done
	actual=$(
		ssh-keygen -y -f "$SSH_IDENTITY" |
			ssh-keygen -lf /dev/stdin -E sha256 |
			awk 'NR == 1 { print $2 }'
	)
	[ "$actual" = "$SSH_FINGERPRINT" ] ||
		fail "SSH identity fingerprint mismatch"
}

provider_field() {
	role=$1
	field=$2
	json_required ".providers.$role.$field"
}

select_provider() {
	role=$1
	PROVIDER_HOST=$(provider_field "$role" host)
	PROVIDER_USER=$(provider_field "$role" user)
	PROVIDER_HOSTNAME=$(provider_field "$role" expected_hostname)
	PROVIDER_FINGERPRINT=$(provider_field "$role" host_ed25519_fingerprint)
	printf '%s' "$PROVIDER_HOST" | LC_ALL=C grep -Eq '^[0-9A-Fa-f:.]+$' ||
		fail "provider host must be an IP literal"
	printf '%s' "$PROVIDER_USER" | LC_ALL=C grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' ||
		fail "provider user is invalid"
	printf '%s' "$PROVIDER_HOSTNAME" |
		LC_ALL=C grep -Eq '^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$' ||
		fail "provider hostname is invalid"
	found=$(
		ssh-keygen -F "$PROVIDER_HOST" -f "$KNOWN_HOSTS" 2>/dev/null |
			awk '!/^#/ { print }' |
			ssh-keygen -lf /dev/stdin -E sha256 2>/dev/null |
			awk '$4 == "(ED25519)" { print $2 }'
	)
	[ "$(printf '%s\n' "$found" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] &&
		[ "$found" = "$PROVIDER_FINGERPRINT" ] ||
		fail "provider host-key pin mismatch"
}

remote() {
	ssh -F /dev/null \
		-i "$SSH_IDENTITY" \
		-o BatchMode=yes -o IdentitiesOnly=yes \
		-o StrictHostKeyChecking=yes \
		-o UserKnownHostsFile="$KNOWN_HOSTS" \
		-o ConnectTimeout=10 \
		-o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
		"$PROVIDER_USER@$PROVIDER_HOST" "$@"
}

copy_to_provider() {
	local_path=$1
	remote_path=$2
	scp -F /dev/null \
		-i "$SSH_IDENTITY" \
		-o BatchMode=yes -o IdentitiesOnly=yes \
		-o StrictHostKeyChecking=yes \
		-o UserKnownHostsFile="$KNOWN_HOSTS" \
		-o ConnectTimeout=10 \
		"$local_path" "$PROVIDER_USER@$PROVIDER_HOST:$remote_path"
}

copy_from_provider() {
	remote_path=$1
	local_path=$2
	umask 077
	scp -F /dev/null -r \
		-i "$SSH_IDENTITY" \
		-o BatchMode=yes -o IdentitiesOnly=yes \
		-o StrictHostKeyChecking=yes \
		-o UserKnownHostsFile="$KNOWN_HOSTS" \
		-o ConnectTimeout=10 \
		"$PROVIDER_USER@$PROVIDER_HOST:$remote_path" "$local_path"
}

build_artifacts() {
	output=$CONFIG_PATH
	[ "${output#/}" != "$output" ] || fail "build output must be absolute"
	[ ! -e "$output" ] || fail "build output must not already exist"
	umask 077
	mkdir "$output"
	cd "$PROJECT_ROOT"
	for package in client webrtc orchestrator canary netprobe; do
		case "$package" in
		client) source=./cmd/winn-leak-v2; binary=winn-leak-v2 ;;
		webrtc) source=./cmd/winn-leak-v2/webrtc; binary=winn-webrtc-v2 ;;
		orchestrator) source=./cmd/winn-leak-v2/orchestrator; binary=winn-leak-orchestrator-v2 ;;
		canary) source=./cmd/winn-leak-v2/hooks/canary; binary=winn-leak-canary-v2 ;;
		netprobe) source=./cmd/winn-leak-v2/hooks/netprobe; binary=winn-leak-netprobe-v2 ;;
		esac
		manifest=$output/$binary.source.sha256
		digest=$(CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
			"$SCRIPT_DIR/source_manifest.sh" "$source" "$manifest")
		if [ "$package" = client ]; then
			CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
				-ldflags "-X main.sourceTreeDigest=$digest" \
				-o "$output/$binary" "$source"
		else
			CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
				-o "$output/$binary" "$source"
		fi
		case "$package" in
		webrtc) chmod 0755 "$output/$binary" ;;
		*) chmod 0700 "$output/$binary" ;;
		esac
		verify=$output/$binary.source.verify.sha256
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
			"$SCRIPT_DIR/source_manifest.sh" "$source" "$verify" >/dev/null
		cmp "$manifest" "$verify" ||
			fail "source tree changed while building $binary"
		rm -f "$verify"
	done
	for script in \
		winn_leak_acceptance_v2_provider_remote.sh \
		winn_leak_acceptance_v2_common.sh \
		winn_leak_acceptance_v2_gateway_hook.sh \
		winn_leak_acceptance_v2_observer_hook.sh \
		winn_leak_acceptance_v2_probe_hook.sh \
		winn_leak_acceptance_v2_recovery_hook.sh; do
		install -m 0700 "$SCRIPT_DIR/$script" "$output/$script"
	done
	(
		cd "$output"
		manifest_next=artifacts.sha256.next
		# The destination is explicitly excluded from find's input set.
		# shellcheck disable=SC2094
		find . -maxdepth 1 -type f \
			! -name artifacts.sha256 \
			! -name "$manifest_next" -print0 |
			sort -z |
			xargs -0 sha256sum >"$manifest_next"
		mv "$manifest_next" artifacts.sha256
	)
	chmod 0600 "$output"/*.sha256
	echo "BUILT output=$output"
}

validate_artifacts() {
	ARTIFACTS=$1
	[ "${ARTIFACTS#/}" != "$ARTIFACTS" ] &&
		[ -d "$ARTIFACTS" ] && [ ! -L "$ARTIFACTS" ] ||
		fail "artifact directory must be absolute and real"
	for name in winn-leak-v2 winn-leak-canary-v2 \
		winn-leak-netprobe-v2 winn-leak-provider-v2; do
		case "$name" in
		winn-leak-provider-v2)
			path=$ARTIFACTS/winn_leak_acceptance_v2_provider_remote.sh
			;;
		*) path=$ARTIFACTS/$name ;;
		esac
		[ -f "$path" ] && [ ! -L "$path" ] ||
			fail "artifact is absent: $path"
	done
	(
		cd "$ARTIFACTS"
		sha256sum -c artifacts.sha256 >/dev/null
	)
}

install_provider() {
	role=$1
	select_provider "$role"
	stage=/tmp/winn-leak-v2-stage-$$-$role
	remote test ! -e "$stage"
	remote install -d -m 0700 "$stage"
	copy_to_provider "$ARTIFACTS/winn-leak-v2" "$stage/winn-leak-v2"
	copy_to_provider "$ARTIFACTS/winn-leak-canary-v2" "$stage/winn-leak-canary-v2"
	copy_to_provider \
		"$ARTIFACTS/winn_leak_acceptance_v2_provider_remote.sh" \
		"$stage/winn-leak-provider-v2"
	client_hash=$(sha256sum "$ARTIFACTS/winn-leak-v2" | awk '{print $1}')
	canary_hash=$(sha256sum "$ARTIFACTS/winn-leak-canary-v2" | awk '{print $1}')
	provider_hash=$(
		sha256sum "$ARTIFACTS/winn_leak_acceptance_v2_provider_remote.sh" |
			awk '{print $1}'
	)
	remote /bin/sh -s -- "$role" "$PROVIDER_HOSTNAME" "$stage" \
		"$client_hash" "$canary_hash" "$provider_hash" <<'REMOTE_INSTALL'
set -eu
role=$1
expected_hostname=$2
stage=$3
client_hash=$4
canary_hash=$5
provider_hash=$6
fail() { echo "remote fixture install: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail "root required"
[ "$(hostname)" = "$expected_hostname" ] || fail "hostname mismatch"
[ "$(systemctl is-active winn-gateway)" = active ] ||
	fail "production gateway service is not active"
[ ! -e /opt/winn-leak-v2 ] &&
	[ ! -e /etc/winn-leak-v2 ] &&
	[ ! -e /run/winn-leak-provider-v2 ] &&
	[ ! -e /var/lib/winn-leak-provider-v2 ] ||
	fail "fixture root already exists"
[ "$(sha256sum "$stage/winn-leak-v2" | awk '{print $1}')" = "$client_hash" ]
[ "$(sha256sum "$stage/winn-leak-canary-v2" | awk '{print $1}')" = "$canary_hash" ]
[ "$(sha256sum "$stage/winn-leak-provider-v2" | awk '{print $1}')" = "$provider_hash" ]
umask 077
install -d -m 0700 /opt/winn-leak-v2/bin /etc/winn-leak-v2
install -m 0700 "$stage/winn-leak-v2" /opt/winn-leak-v2/bin/winn-leak-v2
install -m 0700 "$stage/winn-leak-canary-v2" /opt/winn-leak-v2/bin/winn-leak-canary-v2
install -m 0700 "$stage/winn-leak-provider-v2" /opt/winn-leak-v2/bin/winn-leak-provider-v2
service_pid=$(systemctl show winn-gateway -p MainPID --value)
service_ticks=$(sed 's/^.*) //' "/proc/$service_pid/stat" | awk '{print $20}')
if [ "$role" = gateway ]; then
	install -d -m 0700 /etc/winn-leak-v2/private
	for family in v4 v6; do
		/opt/winn-lab/bin/awg genkey \
			>/etc/winn-leak-v2/private/gateway-$family.key
		/opt/winn-lab/bin/awg pubkey \
			</etc/winn-leak-v2/private/gateway-$family.key \
			>/etc/winn-leak-v2/private/gateway-$family.pub
		/opt/winn-lab/bin/awg genkey |
			/opt/winn-lab/bin/awg pubkey \
			>/etc/winn-leak-v2/private/fixture-client-$family.pub
		/opt/winn-lab/bin/awg genpsk \
			>/etc/winn-leak-v2/private/fixture-$family.psk
	done
	chmod 0600 /etc/winn-leak-v2/private/*
	{
		printf '%s\n' \
			'CONFIG_VERSION=winn-leak-provider-config/v2' \
			'PROVIDER_ROLE=gateway' \
			"EXPECTED_HOSTNAME=$expected_hostname" \
			'WINN_LEAK_BINARY=/opt/winn-leak-v2/bin/winn-leak-v2' \
			'CANARY_BINARY=/opt/winn-leak-v2/bin/winn-leak-canary-v2' \
			'TCPDUMP_BINARY=/usr/bin/tcpdump' \
			'NFT_BINARY=/usr/sbin/nft' \
			'AWG_GO_BINARY=/opt/winn-lab/bin/amneziawg-go' \
			'AWG_BINARY=/opt/winn-lab/bin/awg' \
			'GATEWAY_PEER_MODE=fixture' \
			'GATEWAY_DNS_ZONE=leak-v2.invalid' \
			'GATEWAY_DNS_ANSWER_V4=<NODE_CONTROL_ATL>' \
			'GATEWAY_DNS_ANSWER_V6=<NODE_CONTROL_ATL_V6>' \
			'GATEWAY_V4_INTERFACE_CIDR=10.251.4.1/30' \
			'GATEWAY_V4_CLIENT_CIDR=10.251.4.4/30' \
			'GATEWAY_V4_EGRESS_INTERFACE=eth0' \
			'GATEWAY_V4_LISTEN_PORT=42844' \
			'GATEWAY_V4_PRIVATE_KEY_FILE=/etc/winn-leak-v2/private/gateway-v4.key' \
			'GATEWAY_V4_CLIENT_PUBLIC_KEY_FILE=/etc/winn-leak-v2/private/fixture-client-v4.pub' \
			'GATEWAY_V4_PSK_FILE=/etc/winn-leak-v2/private/fixture-v4.psk' \
			'GATEWAY_V4_DNS_LISTEN=10.251.4.1:53' \
			'GATEWAY_V4_CANARY_LISTEN=10.251.4.1:7007' \
			'GATEWAY_V4_NONCE=11111111111111111111111111111111' \
			'GATEWAY_V6_INTERFACE_CIDR=fd42:251:6::1/126' \
			'GATEWAY_V6_CLIENT_CIDR=fd42:251:6::4/126' \
			'GATEWAY_V6_EGRESS_INTERFACE=eth2' \
			'GATEWAY_V6_LISTEN_PORT=42846' \
			'GATEWAY_V6_PRIVATE_KEY_FILE=/etc/winn-leak-v2/private/gateway-v6.key' \
			'GATEWAY_V6_CLIENT_PUBLIC_KEY_FILE=/etc/winn-leak-v2/private/fixture-client-v6.pub' \
			'GATEWAY_V6_PSK_FILE=/etc/winn-leak-v2/private/fixture-v6.psk' \
			'GATEWAY_V6_DNS_LISTEN=[fd42:251:6::1]:53' \
			'GATEWAY_V6_CANARY_LISTEN=[fd42:251:6::1]:7007' \
			'GATEWAY_V6_NONCE=22222222222222222222222222222222'
	} >/etc/winn-leak-v2/provider.env
else
	{
		printf '%s\n' \
			'CONFIG_VERSION=winn-leak-provider-config/v2' \
			'PROVIDER_ROLE=observer' \
			"EXPECTED_HOSTNAME=$expected_hostname" \
			'WINN_LEAK_BINARY=/opt/winn-leak-v2/bin/winn-leak-v2' \
			'TCPDUMP_BINARY=/usr/bin/tcpdump' \
			'OBSERVER_DNS_ZONE=leak-v2.invalid' \
			'OBSERVER_ANSWER_V4=<NODE_CONTROL_ATL>' \
			'OBSERVER_ANSWER_V6=<NODE_CONTROL_ATL_V6>' \
			'OBSERVER_V4_PUBLIC_IP=<NODE_CONTROL_ATL>' \
			'OBSERVER_V4_INTERFACE=enp1s0' \
			'OBSERVER_V4_HTTP_PORT=46380' \
			'OBSERVER_V4_STUN_PORT=46378' \
			'OBSERVER_V4_DNS_PORT=10534' \
			'OBSERVER_V4_NONCE=33333333333333333333333333333333' \
			'OBSERVER_V4_EXPECTED_PEER=<NODE_EXIT_CHI>' \
			'OBSERVER_V6_PUBLIC_IP=<NODE_CONTROL_ATL_V6>' \
			'OBSERVER_V6_INTERFACE=enp1s0' \
			'OBSERVER_V6_HTTP_PORT=46381' \
			'OBSERVER_V6_STUN_PORT=46379' \
			'OBSERVER_V6_DNS_PORT=10536' \
			'OBSERVER_V6_NONCE=44444444444444444444444444444444' \
			'OBSERVER_V6_EXPECTED_PEER=<NODE_EXIT_CHI_V6>'
	} >/etc/winn-leak-v2/provider.env
fi
chmod 0600 /etc/winn-leak-v2/provider.env
jq -n --arg version winn-leak-fixture-deployment/v2 \
	--arg role "$role" --argjson service_pid "$service_pid" \
	--arg service_ticks "$service_ticks" \
	--arg client_hash "$client_hash" --arg canary_hash "$canary_hash" \
	--arg provider_hash "$provider_hash" \
	'{version:$version,role:$role,
	  service:{pid:$service_pid,start_ticks:$service_ticks},
	  artifacts:{client:$client_hash,canary:$canary_hash,provider:$provider_hash}}' \
	>/etc/winn-leak-v2/deployment.json
chmod 0600 /etc/winn-leak-v2/deployment.json
rm -f "$stage/winn-leak-v2" "$stage/winn-leak-canary-v2" \
	"$stage/winn-leak-provider-v2"
rmdir "$stage"
sync
echo "INSTALLED role=$role"
REMOTE_INSTALL
}

provider_command() {
	role=$1
	command=$2
	run_id=$3
	family=$4
	select_provider "$role"
	remote /opt/winn-leak-v2/bin/winn-leak-provider-v2 \
		"$role" "$command" "$run_id" "$family" fixture
}

collect_provider() {
	role=$1
	run_id=$2
	family=$3
	output=$4
	select_provider "$role"
	remote_path=$(remote /opt/winn-leak-v2/bin/winn-leak-provider-v2 \
		"$role" evidence-path "$run_id" "$family" fixture)
	expected=/var/lib/winn-leak-provider-v2/$role-$run_id-$family-fixture
	[ "$remote_path" = "$expected" ] || fail "unexpected provider evidence path"
	copy_from_provider "$remote_path" "$output/provider-$role"
	find "$output/provider-$role" -type l -print -quit | grep . >/dev/null &&
		fail "provider evidence contains a symlink"
	find "$output/provider-$role" -type d -exec chmod 0700 {} +
	find "$output/provider-$role" -type f -exec chmod 0600 {} +
	remote /opt/winn-leak-v2/bin/winn-leak-provider-v2 \
		"$role" purge "$run_id" "$family" fixture
}

smoke_fixture() {
	run_id=$ARG3
	family=$ARG4
	output=$ARG5
	printf '%s' "$run_id" | LC_ALL=C grep -Eq '^[0-9a-f]{32}$' ||
		fail "smoke RUN_ID must be lowercase 32-hex"
	case "$family" in v4 | v6) ;; *) fail "smoke family must be v4 or v6" ;; esac
	[ "${output#/}" != "$output" ] && [ ! -e "$output" ] ||
		fail "smoke evidence output must be a new absolute path"
	umask 077
	mkdir "$output"
	observer_started=0
	gateway_started=0
	smoke_cleanup() {
		if [ "$gateway_started" -eq 1 ]; then
			provider_command gateway recover "$run_id" "$family" >/dev/null 2>&1 || true
			provider_command gateway stop "$run_id" "$family" >/dev/null 2>&1 || true
		fi
		if [ "$observer_started" -eq 1 ]; then
			provider_command observer stop "$run_id" "$family" >/dev/null 2>&1 || true
		fi
	}
	trap smoke_cleanup EXIT HUP INT TERM
	provider_command observer start "$run_id" "$family"
	observer_started=1
	provider_command observer status "$run_id" "$family"
	provider_command gateway start "$run_id" "$family"
	gateway_started=1
	provider_command gateway status "$run_id" "$family"
	provider_command gateway outage "$run_id" "$family"
	provider_command gateway status "$run_id" "$family"
	provider_command gateway recover "$run_id" "$family"
	provider_command gateway status "$run_id" "$family"
	provider_command gateway stop "$run_id" "$family"
	gateway_started=0
	provider_command observer stop "$run_id" "$family"
	observer_started=0
	collect_provider gateway "$run_id" "$family" "$output"
	collect_provider observer "$run_id" "$family" "$output"
	provider_command gateway residue "$run_id" "$family"
	provider_command observer residue "$run_id" "$family"
	(
		cd "$output"
		manifest_next=evidence.sha256.next
		# The destination is explicitly excluded from find's input set.
		# shellcheck disable=SC2094
		find . -type f \
			! -name evidence.sha256 \
			! -name "$manifest_next" -print0 |
			sort -z |
			xargs -0 sha256sum >"$manifest_next"
		mv "$manifest_next" evidence.sha256
	)
	chmod 0600 "$output/evidence.sha256"
	trap - EXIT HUP INT TERM
	echo "SMOKE_PASS family=$family evidence=$output"
}

remove_provider() {
	role=$1
	select_provider "$role"
	remote /bin/sh -s -- "$role" "$PROVIDER_HOSTNAME" <<'REMOTE_REMOVE'
set -eu
role=$1
expected_hostname=$2
fail() { echo "remote fixture removal: $*" >&2; exit 1; }
[ "$(hostname)" = "$expected_hostname" ] || fail "hostname mismatch"
marker=/etc/winn-leak-v2/deployment.json
[ -f "$marker" ] || fail "deployment marker is absent"
[ "$(jq -r '.version' "$marker")" = winn-leak-fixture-deployment/v2 ] &&
	[ "$(jq -r '.role' "$marker")" = "$role" ] ||
	fail "deployment marker mismatch"
[ ! -e /etc/winn-leak-v2/peer-prepared.json ] ||
	fail "acceptance peer material must be cleaned before fixture removal"
[ "$(systemctl is-active winn-gateway)" = active ] ||
	fail "production gateway service is inactive"
service_pid=$(jq -r '.service.pid' "$marker")
service_ticks=$(jq -r '.service.start_ticks' "$marker")
[ "$(systemctl show winn-gateway -p MainPID --value)" = "$service_pid" ] ||
	fail "production service PID changed"
[ "$(sed 's/^.*) //' "/proc/$service_pid/stat" | awk '{print $20}')" = "$service_ticks" ] ||
	fail "production service identity changed"
for root in /run/winn-leak-provider-v2 /var/lib/winn-leak-provider-v2; do
	if [ -e "$root" ]; then
		[ -d "$root" ] && [ -z "$(find "$root" -mindepth 1 -print -quit)" ] ||
			fail "runtime/evidence root is not empty"
	fi
done
nft list tables | grep -E 'wlv2[fon][46]?_' >/dev/null &&
	fail "fixture nftables residue remains"
ufw status numbered 2>/dev/null | grep -F 'wlv2' >/dev/null &&
	fail "fixture UFW residue remains"
client_hash=$(jq -r '.artifacts.client' "$marker")
canary_hash=$(jq -r '.artifacts.canary' "$marker")
provider_hash=$(jq -r '.artifacts.provider' "$marker")
[ "$(sha256sum /opt/winn-leak-v2/bin/winn-leak-v2 | awk '{print $1}')" = "$client_hash" ]
[ "$(sha256sum /opt/winn-leak-v2/bin/winn-leak-canary-v2 | awk '{print $1}')" = "$canary_hash" ]
[ "$(sha256sum /opt/winn-leak-v2/bin/winn-leak-provider-v2 | awk '{print $1}')" = "$provider_hash" ]
rm -f /opt/winn-leak-v2/bin/winn-leak-v2 \
	/opt/winn-leak-v2/bin/winn-leak-canary-v2 \
	/opt/winn-leak-v2/bin/winn-leak-provider-v2
rmdir /opt/winn-leak-v2/bin /opt/winn-leak-v2
if [ "$role" = gateway ]; then
	for name in gateway-v4.key gateway-v4.pub fixture-client-v4.pub fixture-v4.psk \
		gateway-v6.key gateway-v6.pub fixture-client-v6.pub fixture-v6.psk; do
		rm -f "/etc/winn-leak-v2/private/$name"
	done
	rmdir /etc/winn-leak-v2/private
fi
rm -f /etc/winn-leak-v2/provider.env /etc/winn-leak-v2/deployment.json
rmdir /etc/winn-leak-v2
for root in /run/winn-leak-provider-v2 /var/lib/winn-leak-provider-v2; do
	[ ! -e "$root" ] || rmdir "$root"
done
echo "REMOVED role=$role"
REMOTE_REMOVE
}

prepare_client_material() {
	marker=$(json_required '.client.disposable_marker')
	expected_hostname=$(json_required '.client.expected_hostname')
	awg_binary=$(json_required '.client.awg_binary')
	private_root=$(json_required '.client.private_root')
	[ "$(uname -s)" = Linux ] && [ "$(id -u)" -eq 0 ] ||
		fail "client material must be prepared as root on Linux"
	[ -f "$marker" ] && [ "$(hostname)" = "$expected_hostname" ] ||
		fail "client material refused outside the marked disposable client"
	[ -x "$awg_binary" ] && [ -f "$awg_binary" ] && [ ! -L "$awg_binary" ] ||
		fail "client AWG executable is invalid"
	[ "${private_root#/}" != "$private_root" ] && [ ! -e "$private_root" ] ||
		fail "client private root must be a new absolute path"
	umask 077
	mkdir "$private_root"
	chmod 0700 "$private_root"
	for family in v4 v6; do
		"$awg_binary" genkey >"$private_root/client-$family.key"
		"$awg_binary" pubkey \
			<"$private_root/client-$family.key" \
			>"$private_root/client-$family.pub"
		"$awg_binary" genpsk >"$private_root/client-$family.psk"
		chmod 0600 "$private_root/client-$family.key" \
			"$private_root/client-$family.pub" \
			"$private_root/client-$family.psk"
	done
	select_provider gateway
	stage=/tmp/winn-leak-v2-peer-$$
	remote test ! -e "$stage"
	remote install -d -m 0700 "$stage"
	for family in v4 v6; do
		copy_to_provider "$private_root/client-$family.pub" \
			"$stage/client-$family.pub"
		copy_to_provider "$private_root/client-$family.psk" \
			"$stage/client-$family.psk"
		copy_from_provider \
			"/etc/winn-leak-v2/private/gateway-$family.pub" \
			"$private_root/gateway-$family.pub"
		chmod 0600 "$private_root/gateway-$family.pub"
	done
	remote /bin/sh -s -- "$stage" <<'REMOTE_PREPARE_PEER'
set -eu
stage=$1
fail() { echo "remote peer preparation: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ]
config=/etc/winn-leak-v2/provider.env
[ -f "$config" ] && [ "$(stat -c '%a' "$config")" = 600 ] ||
	fail "provider config is absent or insecure"
[ "$(grep -c '^GATEWAY_PEER_MODE=fixture$' "$config")" -eq 1 ] ||
	fail "provider is not in fixture peer mode"
for root in /run/winn-leak-provider-v2 /var/lib/winn-leak-provider-v2; do
	[ ! -e "$root" ] || [ -z "$(find "$root" -mindepth 1 -print -quit)" ] ||
		fail "provider runtime/evidence is not empty"
done
for family in v4 v6; do
	public="$stage/client-$family.pub"
	psk="$stage/client-$family.psk"
	[ -f "$public" ] && [ -f "$psk" ]
	[ "$(stat -c '%a' "$public")" = 600 ] &&
		[ "$(stat -c '%a' "$psk")" = 600 ] ||
		fail "staged peer material is insecure"
	tr -d '\r\n' <"$public" | grep -Eq '^[A-Za-z0-9+/]{43}=$' ||
		fail "staged public key is invalid"
	tr -d '\r\n' <"$psk" | grep -Eq '^[A-Za-z0-9+/]{43}=$' ||
		fail "staged PSK is invalid"
	install -m 0600 "$public" \
		"/etc/winn-leak-v2/private/acceptance-client-$family.pub"
	install -m 0600 "$psk" \
		"/etc/winn-leak-v2/private/acceptance-$family.psk"
done
for variable in GATEWAY_PEER_MODE \
	GATEWAY_V4_CLIENT_PUBLIC_KEY_FILE GATEWAY_V4_PSK_FILE \
	GATEWAY_V6_CLIENT_PUBLIC_KEY_FILE GATEWAY_V6_PSK_FILE; do
	[ "$(grep -c "^$variable=" "$config")" -eq 1 ] ||
		fail "provider config field is missing or duplicated: $variable"
done
next=/etc/winn-leak-v2/provider.env.next
awk '
	/^GATEWAY_PEER_MODE=/ {
		print "GATEWAY_PEER_MODE=acceptance"; next
	}
	/^GATEWAY_V4_CLIENT_PUBLIC_KEY_FILE=/ {
		print "GATEWAY_V4_CLIENT_PUBLIC_KEY_FILE=/etc/winn-leak-v2/private/acceptance-client-v4.pub"; next
	}
	/^GATEWAY_V4_PSK_FILE=/ {
		print "GATEWAY_V4_PSK_FILE=/etc/winn-leak-v2/private/acceptance-v4.psk"; next
	}
	/^GATEWAY_V6_CLIENT_PUBLIC_KEY_FILE=/ {
		print "GATEWAY_V6_CLIENT_PUBLIC_KEY_FILE=/etc/winn-leak-v2/private/acceptance-client-v6.pub"; next
	}
	/^GATEWAY_V6_PSK_FILE=/ {
		print "GATEWAY_V6_PSK_FILE=/etc/winn-leak-v2/private/acceptance-v6.psk"; next
	}
	{ print }
' "$config" >"$next"
chmod 0600 "$next"
mv "$next" "$config"
jq -n --arg version winn-leak-peer-prepared/v2 \
	'{version:$version}' >/etc/winn-leak-v2/peer-prepared.json
chmod 0600 /etc/winn-leak-v2/peer-prepared.json
rm -f "$stage/client-v4.pub" "$stage/client-v4.psk" \
	"$stage/client-v6.pub" "$stage/client-v6.psk"
rmdir "$stage"
sync
echo "PEER_PREPARED"
REMOTE_PREPARE_PEER
	jq -n \
		--arg version winn-leak-client-material/v2 \
		--arg v4_private "$private_root/client-v4.key" \
		--arg v4_psk "$private_root/client-v4.psk" \
		--arg v4_gateway_public "$private_root/gateway-v4.pub" \
		--arg v6_private "$private_root/client-v6.key" \
		--arg v6_psk "$private_root/client-v6.psk" \
		--arg v6_gateway_public "$private_root/gateway-v6.pub" \
		'{version:$version,
		  v4:{client_private_key_file:$v4_private,psk_file:$v4_psk,
		      gateway_public_key_file:$v4_gateway_public},
		  v6:{client_private_key_file:$v6_private,psk_file:$v6_psk,
		      gateway_public_key_file:$v6_gateway_public}}' \
		>"$private_root/material.json"
	chmod 0600 "$private_root/material.json"
	sync "$private_root/material.json"
	echo "CLIENT_MATERIAL_PREPARED path=$private_root/material.json"
}

cleanup_client_material() {
	marker=$(json_required '.client.disposable_marker')
	expected_hostname=$(json_required '.client.expected_hostname')
	private_root=$(json_required '.client.private_root')
	[ "$(uname -s)" = Linux ] && [ "$(id -u)" -eq 0 ] ||
		fail "client material cleanup requires root on Linux"
	[ -f "$marker" ] && [ "$(hostname)" = "$expected_hostname" ] ||
		fail "client material cleanup refused outside the marked disposable client"
	[ -f "$private_root/material.json" ] &&
		[ "$(jq -r '.version' "$private_root/material.json")" = winn-leak-client-material/v2 ] ||
		fail "client material marker is absent or invalid"
	select_provider gateway
	remote /bin/sh -s <<'REMOTE_CLEANUP_PEER'
set -eu
fail() { echo "remote peer cleanup: $*" >&2; exit 1; }
config=/etc/winn-leak-v2/provider.env
[ -f /etc/winn-leak-v2/peer-prepared.json ] &&
	[ "$(jq -r '.version' /etc/winn-leak-v2/peer-prepared.json)" = winn-leak-peer-prepared/v2 ] ||
	fail "remote peer marker is absent"
[ "$(grep -c '^GATEWAY_PEER_MODE=acceptance$' "$config")" -eq 1 ] ||
	fail "provider is not in acceptance peer mode"
for root in /run/winn-leak-provider-v2 /var/lib/winn-leak-provider-v2; do
	[ ! -e "$root" ] || [ -z "$(find "$root" -mindepth 1 -print -quit)" ] ||
		fail "provider runtime/evidence is not empty"
done
next=/etc/winn-leak-v2/provider.env.next
awk '
	/^GATEWAY_PEER_MODE=/ {
		print "GATEWAY_PEER_MODE=fixture"; next
	}
	/^GATEWAY_V4_CLIENT_PUBLIC_KEY_FILE=/ {
		print "GATEWAY_V4_CLIENT_PUBLIC_KEY_FILE=/etc/winn-leak-v2/private/fixture-client-v4.pub"; next
	}
	/^GATEWAY_V4_PSK_FILE=/ {
		print "GATEWAY_V4_PSK_FILE=/etc/winn-leak-v2/private/fixture-v4.psk"; next
	}
	/^GATEWAY_V6_CLIENT_PUBLIC_KEY_FILE=/ {
		print "GATEWAY_V6_CLIENT_PUBLIC_KEY_FILE=/etc/winn-leak-v2/private/fixture-client-v6.pub"; next
	}
	/^GATEWAY_V6_PSK_FILE=/ {
		print "GATEWAY_V6_PSK_FILE=/etc/winn-leak-v2/private/fixture-v6.psk"; next
	}
	{ print }
' "$config" >"$next"
chmod 0600 "$next"
mv "$next" "$config"
rm -f /etc/winn-leak-v2/private/acceptance-client-v4.pub \
	/etc/winn-leak-v2/private/acceptance-v4.psk \
	/etc/winn-leak-v2/private/acceptance-client-v6.pub \
	/etc/winn-leak-v2/private/acceptance-v6.psk \
	/etc/winn-leak-v2/peer-prepared.json
sync
echo "PEER_CLEANED"
REMOTE_CLEANUP_PEER
	rm -f "$private_root/client-v4.key" "$private_root/client-v4.pub" \
		"$private_root/client-v4.psk" "$private_root/gateway-v4.pub" \
		"$private_root/client-v6.key" "$private_root/client-v6.pub" \
		"$private_root/client-v6.psk" "$private_root/gateway-v6.pub" \
		"$private_root/material.json"
	rmdir "$private_root"
	echo "CLIENT_MATERIAL_CLEAN"
}

run_acceptance() {
	acceptance_config=$ARG3
	marker=$(json_required '.client.disposable_marker')
	expected_hostname=$(json_required '.client.expected_hostname')
	orchestrator=$(json_required '.client.orchestrator_binary')
	private_root=$(json_required '.client.private_root')
	[ "$(uname -s)" = Linux ] && [ "$(id -u)" -eq 0 ] ||
		fail "acceptance run requires root on Linux"
	[ -f "$marker" ] && [ "$(hostname)" = "$expected_hostname" ] ||
		fail "acceptance run refused outside the marked disposable client"
	[ -f "$private_root/material.json" ] &&
		[ "$(jq -r '.version' "$private_root/material.json")" = winn-leak-client-material/v2 ] ||
		fail "acceptance run requires securely matched client/provider peer material"
	exec "$orchestrator" -config="$acceptance_config"
}

case "$ACTION" in
build)
	[ "$#" -eq 2 ] || fail "usage: $0 build /new/output/directory"
	CONFIG_PATH=$2
	build_artifacts
	;;
install-fixture)
	[ "$#" -eq 3 ] || fail "usage: $0 install-fixture CONFIG ARTIFACT_DIR"
	validate_config
	validate_artifacts "$ARG3"
	install_provider gateway
	install_provider observer
	;;
smoke)
	[ "$#" -eq 5 ] ||
		fail "usage: $0 smoke CONFIG RUN_ID FAMILY /new/evidence/directory"
	validate_config
	smoke_fixture
	;;
remove-fixture)
	[ "$#" -eq 2 ] || fail "usage: $0 remove-fixture CONFIG"
	validate_config
	remove_provider gateway
	remove_provider observer
	;;
prepare-client)
	[ "$#" -eq 2 ] || fail "usage: $0 prepare-client CONFIG"
	validate_config
	prepare_client_material
	;;
cleanup-client)
	[ "$#" -eq 2 ] || fail "usage: $0 cleanup-client CONFIG"
	validate_config
	cleanup_client_material
	;;
run)
	[ "$#" -eq 3 ] || fail "usage: $0 run DEPLOY_CONFIG ACCEPTANCE_CONFIG"
	validate_config
	run_acceptance
	;;
*) fail "action must be build, install-fixture, smoke, remove-fixture, prepare-client, cleanup-client, or run" ;;
esac
