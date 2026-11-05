#!/usr/bin/env bash
# Win's VPN Spain Server Crypto Payments Setup (BTCPay Server + Monero Wallet RPC)
# Target: Spain Data Plane (NODE_IP_ES1, Ubuntu 24.04 LTS x86_64)
# Roles:
#   - BTCPay Server (Bitcoin + Dash) with pruned storage (opt-save-storage-s)
#   - Monero Wallet RPC (staged view-only wallet opened by --wallet-file, loopback
#     bind, HTTP Digest Authentication, /json_rpc behind Cloudflare Access)
#   - Nginx reverse proxy + Cloudflare Tunnel integration
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
LOG_FILE="/var/log/winsvpn/spain_crypto_setup.log"
COMMERCE_DIR="/etc/winsvpn/commerce"
MONERO_DIR="${COMMERCE_DIR}/monero"
MONERO_WALLET_DIR="/var/lib/monero/wallet"
# Fleet reset TP-P3: the view-only wallet the daemon opens, and its password
# file. Both are staged by the owner (generated offline from the view key);
# this installer never generates wallet keys.
MONERO_WALLET_NAME="${MONERO_WALLET_NAME:-winsvpn_view_wallet}"
MONERO_WALLET_PASSWORD_FILE="${MONERO_WALLET_DIR}/wallet.pass"
MONERO_CLI_VERSION="v0.18.5.1"
MONERO_CLI_SHA256="22a7dda7b0cb699fdd6b7674c3b4a4465b337cc98a54983523b759e1e7cc9958"
BTCPAY_DIR="${COMMERCE_DIR}/btcpay"
BTCPAY_DOCKER_DIR="${BTCPAY_DIR}/btcpayserver-docker"
NGINX_CONF_AVAILABLE="/etc/nginx/sites-available/wins-crypto-payments.conf"
NGINX_CONF_ENABLED="/etc/nginx/sites-enabled/wins-crypto-payments.conf"

info() {
    printf '[INFO] %s\n' "$*"
}

warn() {
    printf '[WARN] %s\n' "$*" >&2
}

err() {
    printf '[ERR] %s\n' "$*" >&2
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root."
        exit 1
    fi
}

require_dependencies() {
    info "Verifying base dependencies..."
    # Binary names and package names are separate constants (OI-35): the check
    # always tests the binary, the install always names the distro package.
    local missing_pkgs=()
    command -v curl   >/dev/null 2>&1 || missing_pkgs+=(curl)
    command -v bzip2  >/dev/null 2>&1 || missing_pkgs+=(bzip2)
    command -v tar    >/dev/null 2>&1 || missing_pkgs+=(tar)
    command -v jq     >/dev/null 2>&1 || missing_pkgs+=(jq)
    command -v docker >/dev/null 2>&1 || missing_pkgs+=(docker.io)
    command -v git    >/dev/null 2>&1 || missing_pkgs+=(git)
    command -v nginx  >/dev/null 2>&1 || missing_pkgs+=(nginx)

    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        info "Installing missing dependencies: ${missing_pkgs[*]}"
        apt-get update -qq
        apt-get install -y -qq "${missing_pkgs[@]}"
    fi

    if ! docker compose version >/dev/null 2>&1; then
        info "Installing docker-compose-plugin..."
        apt-get update -qq
        apt-get install -y -qq docker-compose-plugin
    fi
}

setup_directories() {
    info "Preparing directory tree..."
    mkdir -p /var/log/winsvpn
    mkdir -p "${COMMERCE_DIR}"
    chmod 0700 "${COMMERCE_DIR}"
    mkdir -p "${MONERO_DIR}"
    chmod 0700 "${MONERO_DIR}"
    mkdir -p "${BTCPAY_DIR}"
    chmod 0700 "${BTCPAY_DIR}"
}

setup_monero_service() {
    info "Configuring Monero view-only wallet RPC service..."

    # Create system user if absent
    if ! id -u monero-wallet >/dev/null 2>&1; then
        useradd -r -s /usr/sbin/nologin -d /var/lib/monero -m monero-wallet
    fi

    mkdir -p "${MONERO_WALLET_DIR}"
    chmod 0700 /var/lib/monero "${MONERO_WALLET_DIR}"
    chown -R monero-wallet:monero-wallet /var/lib/monero

    # Download and verify official Monero CLI binaries if not present
    if [[ ! -x /usr/local/bin/monero-wallet-rpc ]]; then
        local archive_name="monero-linux-x64-${MONERO_CLI_VERSION}.tar.bz2"
        local download_url="https://downloads.getmonero.org/cli/${archive_name}"

        # OI-2 hardening (Round 36 treaty): the archive is downloaded and
        # extracted only inside a private mktemp root, so a local account can
        # never preplant a binary at a predictable path that this script then
        # installs as root.
        local tmp_root
        tmp_root="$(mktemp -d /tmp/wins-monero.XXXXXXXX)"
        local tmp_archive="${tmp_root}/${archive_name}"

        info "Downloading Monero CLI ${MONERO_CLI_VERSION}..."
        curl -sSL -o "${tmp_archive}" "${download_url}"

        info "Verifying SHA256 checksum..."
        local calc_sha256
        calc_sha256="$(sha256sum "${tmp_archive}" | awk '{print $1}')"
        if [[ "${calc_sha256}" != "${MONERO_CLI_SHA256}" ]]; then
            err "SHA256 checksum mismatch for Monero CLI archive: expected ${MONERO_CLI_SHA256}, got ${calc_sha256}"
            rm -rf "${tmp_root}"
            exit 1
        fi

        info "Extracting monero-wallet-rpc..."
        local extract_dir="${tmp_root}/extract"
        mkdir -m 0700 "${extract_dir}"
        tar -xjf "${tmp_archive}" -C "${extract_dir}"
        local -a rpc_bins=()
        mapfile -t rpc_bins < <(find "${extract_dir}" -xdev -type f -name monero-wallet-rpc -print)
        if [[ ${#rpc_bins[@]} -ne 1 ]]; then
            err "archive must contain exactly one monero-wallet-rpc, found ${#rpc_bins[@]}"
            rm -rf "${tmp_root}"
            exit 1
        fi
        local rpc_bin="${rpc_bins[0]}"
        if [[ -L "${rpc_bin}" || ! -f "${rpc_bin}" ]]; then
            err "monero-wallet-rpc candidate is not a regular file"
            rm -rf "${tmp_root}"
            exit 1
        fi

        install -m 0755 "${rpc_bin}" /usr/local/bin/monero-wallet-rpc
        rm -rf "${tmp_root}"
        info "monero-wallet-rpc installed successfully."
    fi

    # Generate or load credentials
    local creds_file="${MONERO_DIR}/monero_rpc_auth.env"
    local rpc_user="winsmonero"
    local rpc_pass=""
    if [[ -f "${creds_file}" ]]; then
        # shellcheck disable=SC1090
        source "${creds_file}"
        rpc_user="${MONERO_WALLET_RPC_USER:-winsmonero}"
        rpc_pass="${MONERO_WALLET_RPC_PASS:-}"
    fi

    if [[ -z "${rpc_pass}" ]]; then
        rpc_pass="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
        cat > "${creds_file}" <<EOF
# Generated Monero RPC credentials for Win's VPN Spain node
MONERO_WALLET_RPC_USER="${rpc_user}"
MONERO_WALLET_RPC_PASS="${rpc_pass}"
MONERO_WALLET_RPC_PORT="18083"
EOF
        chmod 0600 "${creds_file}"
        chown root:root "${creds_file}"
    fi

    # OI-2 (Round 36 treaty): the credential is delivered to the daemon through
    # a --config-file owned by the service account, never through the unit
    # file, the process argument vector, or stdout. Root's generator env file
    # stays in place for the RPC probe below; this config is what the daemon
    # reads at runtime. The heredoc runs under umask 077 (Round 37
    # cross-examination): the default root umask would briefly expose the file
    # world-readable between creation and the chmod that follows it.
    local rpc_conf="/var/lib/monero/monero-wallet-rpc.conf"
    # Fleet reset TP-P3: the daemon must have a wallet OPEN. --wallet-dir alone
    # opens nothing, so every hub create-order failed. Open the staged
    # view-only wallet by --wallet-file, exactly as the working Spain unit
    # does. A view-only wallet cannot spend, so an open wallet exposes no
    # funds. Refuse anything that is not a staged regular file: root changes
    # the mode of these paths inside a directory the service account owns.
    [[ "${MONERO_WALLET_NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || {
        err "MONERO_WALLET_NAME must be a plain file name (letters, digits, dot, underscore, dash)."
        exit 1
    }
    local wallet_file="${MONERO_WALLET_DIR}/${MONERO_WALLET_NAME}" staged
    for staged in "${wallet_file}.keys" "${MONERO_WALLET_PASSWORD_FILE}"; do
        if [[ -L "${staged}" || ! -f "${staged}" || ! -s "${staged}" ]]; then
            err "Stage the view-only wallet ${wallet_file} (with ${wallet_file}.keys) and its password file ${MONERO_WALLET_PASSWORD_FILE} as regular files first; this installer never generates wallet keys."
            exit 1
        fi
    done
    if [[ -L "${wallet_file}" || ( -e "${wallet_file}" && ! -f "${wallet_file}" ) ]]; then
        err "${wallet_file} must be a regular file (or absent until the daemon writes its cache)."
        exit 1
    fi
    for staged in "${wallet_file}" "${wallet_file}.keys" "${MONERO_WALLET_PASSWORD_FILE}"; do
        [[ -f "${staged}" ]] || continue
        chown -h monero-wallet:monero-wallet "${staged}"
        chmod 0600 "${staged}"
    done
    (
        umask 077
        cat > "${rpc_conf}" <<EOF
# Monero wallet RPC runtime configuration (credential-bearing, service-owned)
rpc-login=${rpc_user}:${rpc_pass}
rpc-bind-ip=127.0.0.1
rpc-bind-port=18083
daemon-address=nodes.hashvault.pro:18081
untrusted-daemon=1
log-file=/var/log/winsvpn/monero-wallet-rpc.log
max-log-file-size=10485760
EOF
    )
    chown monero-wallet:monero-wallet "${rpc_conf}"
    chmod 0600 "${rpc_conf}"

    # OI-16 (Round 36 treaty): provision the exact log file the service writes
    # so the root-owned /var/log/winsvpn directory never blocks startup.
    local monero_log="/var/log/winsvpn/monero-wallet-rpc.log"
    if [[ ! -e "${monero_log}" ]]; then
        install -o monero-wallet -g monero-wallet -m 0600 /dev/null "${monero_log}"
    fi
    chown monero-wallet:monero-wallet "${monero_log}"
    chmod 0600 "${monero_log}"

    # Setup systemd service unit (no credential content; installed 0640)
    cat > /etc/systemd/system/monero-wallet-rpc.service <<EOF
[Unit]
Description=Win's VPN Monero View-Only Wallet RPC
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=monero-wallet
Group=monero-wallet
ExecStart=/usr/local/bin/monero-wallet-rpc \\
    --config-file ${rpc_conf} \\
    --wallet-file ${wallet_file} \\
    --password-file ${MONERO_WALLET_PASSWORD_FILE} \\
    --non-interactive
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${MONERO_WALLET_DIR} /var/log/winsvpn
MemoryHigh=512M
MemoryMax=768M

[Install]
WantedBy=multi-user.target
EOF
    chown root:root /etc/systemd/system/monero-wallet-rpc.service
    chmod 0640 /etc/systemd/system/monero-wallet-rpc.service

    systemctl daemon-reload
    systemctl enable monero-wallet-rpc.service
    systemctl restart monero-wallet-rpc.service
    if ! runuser -u monero-wallet -- test -w "${monero_log}"; then
        err "Monero service log is not writable by monero-wallet"
        exit 1
    fi
    if ! systemctl is-active --quiet monero-wallet-rpc.service; then
        journalctl -u monero-wallet-rpc.service -n 30 --no-pager >&2
        err "monero-wallet-rpc.service failed to start"
        exit 1
    fi
    info "monero-wallet-rpc service started."
    # TUNNEL-SPEED-2 OI-4: the data-plane installer renders
    # WINN3_GATEWAY_DEDICATED=0 (capped gateway memory) only where this unit
    # exists, and it resolves memory when it writes the gateway unit.
    if [[ -f /etc/systemd/system/winn3-gateway.service ]]; then
        warn "winn3-gateway.service is installed on this host: re-run the data-plane installer's winn3 gateway --start (wins_data_plane_setup_ONETOUCH.sh) so the gateway's memory is re-resolved with the payment server present (dedicated 0)."
    fi
}

setup_btcpay_server() {
    info "Configuring BTCPay Server Docker deployment..."

    # OI-1 (Round 36 treaty): this privileged installer no longer clones and
    # executes upstream code. The operator stages a reviewed checkout, and the
    # installer verifies its identity and cleanliness before running anything
    # from it.
    : "${BTCPAY_REVIEWED_COMMIT:?BTCPAY_REVIEWED_COMMIT must name the reviewed 40-hex commit of the staged btcpayserver-docker checkout}"
    [[ "${BTCPAY_REVIEWED_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || {
        err "BTCPAY_REVIEWED_COMMIT must be exactly 40 lowercase hexadecimal characters"
        exit 1
    }
    if [[ ! -d "${BTCPAY_DOCKER_DIR}/.git" ]]; then
        err "Pre-stage the reviewed btcpayserver-docker checkout at ${BTCPAY_DOCKER_DIR}; this installer does not clone code"
        exit 1
    fi
    local actual_commit
    actual_commit="$(git -C "${BTCPAY_DOCKER_DIR}" rev-parse HEAD)"
    [[ "${actual_commit}" == "${BTCPAY_REVIEWED_COMMIT}" ]] || {
        err "BTCPay checkout is at ${actual_commit}, expected reviewed ${BTCPAY_REVIEWED_COMMIT}"
        exit 1
    }
    git -C "${BTCPAY_DOCKER_DIR}" diff --quiet || {
        err "BTCPay checkout carries uncommitted changes; refusing to run"
        exit 1
    }
    git -C "${BTCPAY_DOCKER_DIR}" diff --cached --quiet || {
        err "BTCPay checkout carries staged changes; refusing to run"
        exit 1
    }

    local env_file="${BTCPAY_DIR}/btcpay.env"
    cat > "${env_file}" <<EOF
# BTCPay Server configuration for Win's VPN Spain Node
export BTCPAY_HOST="btcpay.winsvpn.org"
export NBITCOIN_NETWORK="mainnet"
export BTCPAYGEN_CRYPTO1="btc"
export BTCPAYGEN_CRYPTO2="dash"
export BTCPAYGEN_REVERSEPROXY="none"
export BTCPAYGEN_ADDITIONAL_FRAGMENTS="opt-save-storage-s"
export BTCPAY_ENABLE_SSH=false
EOF
    chmod 0600 "${env_file}"

    # Generate docker compose configuration
    info "Generating BTCPay Server docker-compose file with btc and dash..."
    (
        cd "${BTCPAY_DOCKER_DIR}"
        # shellcheck disable=SC1090
        source "${env_file}"
        . ./btcpay-setup.sh -i
    )

    info "BTCPay Server generation complete."
}

setup_nginx_proxy() {
    info "Configuring local Nginx reverse proxy for crypto services..."

    cat > "${NGINX_CONF_AVAILABLE}" <<'EOF'
# Win's VPN Crypto Payment Services Reverse Proxy
# Local proxy routing for BTCPay Server and Monero Wallet RPC behind Cloudflare Tunnel

server {
    listen 127.0.0.1:23000 default_server;
    server_name btcpay.winsvpn.org _;

    access_log off;
    error_log /var/log/nginx/crypto-payments.error.log warn;

    client_max_body_size 10m;

    # Forward BTCPay Server requests to local container port
    location / {
        proxy_pass http://127.0.0.1:49392;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}

server {
    listen 127.0.0.1:23001 default_server;
    server_name monero-rpc.winsvpn.org;

    # Fleet reset TP-P3/D7: the wallet RPC listens on loopback only. The hub
    # reaches it as https://monero-rpc.winsvpn.org/json_rpc through the commerce
    # tunnel; that hostname is bound to a Cloudflare Access service-token
    # policy, and the wallet RPC itself requires HTTP digest auth. (OI-11 had
    # moved hub access to a WireGuard management path that never existed: the
    # hand-made wghub0 link never completed a handshake.) FLEET1 Turn 2: the
    # wallet has its OWN loopback listener. btcpay.winsvpn.org is public with
    # no Access policy and its tunnel ingress rule points at 23000, so no Host
    # header on 23000 can ever reach the wallet; only the ingress rule for
    # monero-rpc.winsvpn.org (service http://127.0.0.1:23001) does. An ingress
    # still pointing monero-rpc at 23000 reaches BTCPay, never the wallet. The
    # Access headers are dropped here so the service token never reaches the
    # wallet daemon.
    access_log off;
    error_log /var/log/nginx/crypto-payments.error.log warn;

    client_max_body_size 64k;

    location = /json_rpc {
        proxy_pass http://127.0.0.1:18083;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header CF-Access-Client-Id "";
        proxy_set_header CF-Access-Client-Secret "";
        proxy_read_timeout 60s;
    }

    location / {
        return 404;
    }
}
EOF

    ln -sf "${NGINX_CONF_AVAILABLE}" "${NGINX_CONF_ENABLED}"
    nginx -t
    systemctl reload nginx
    info "Nginx proxy configuration reloaded."
}

verify_services() {
    info "Verifying services status..."

    # Check Monero Wallet RPC
    local creds_file="${MONERO_DIR}/monero_rpc_auth.env"
    if [[ -f "${creds_file}" ]]; then
        # shellcheck disable=SC1090
        source "${creds_file}"
        info "Testing Monero RPC loopback endpoint..."
        local monero_test
        monero_test="$(curl -s --digest -u "${MONERO_WALLET_RPC_USER}:${MONERO_WALLET_RPC_PASS}" \
            -X POST http://127.0.0.1:18083/json_rpc \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' || true)"
        info "Monero RPC probe result: ${monero_test}"
    fi

    # Fleet reset TP-P6: nginx proxies to 127.0.0.1:49392; prove the
    # btcpayserver container is published there, or btcpay.winsvpn.org answers
    # 502 behind the tunnel.
    local btcpay_ready="" _attempt
    for _attempt in $(seq 1 60); do
        btcpay_ready="$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://127.0.0.1:49392/ 2>/dev/null || true)"
        [[ "${btcpay_ready}" =~ ^(200|302)$ ]] && break
        sleep 5
    done
    [[ "${btcpay_ready}" =~ ^(200|302)$ ]] || {
        err "BTCPay is not answering on 127.0.0.1:49392 (got ${btcpay_ready:-none}); inspect 'docker ps' port bindings before pointing the hub at this host."
        exit 1
    }

    # Check Nginx proxy port
    if curl -sI http://127.0.0.1:23000 >/dev/null 2>&1; then
        info "Nginx local proxy is listening on 127.0.0.1:23000."
    else
        warn "Nginx local proxy probe returned non-zero (service may still be initializing)."
    fi

    # FLEET1 Turn 2: the wallet RPC answers (its digest challenge) only on its
    # own listener, 127.0.0.1:23001, and never on the public BTCPay listener,
    # whatever Host a request carries.
    local wallet_proxy="" host headers
    wallet_proxy="$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' -X POST http://127.0.0.1:23001/json_rpc 2>/dev/null || true)"
    [[ "${wallet_proxy}" == "401" ]] || {
        err "nginx 127.0.0.1:23001/json_rpc answered ${wallet_proxy:-nothing}, expected the wallet RPC's digest challenge (401)."
        exit 1
    }
    for host in btcpay.winsvpn.org monero-rpc.winsvpn.org localhost; do
        headers="$(curl -s -o /dev/null -D - --max-time 5 -X POST -H "Host: ${host}" http://127.0.0.1:23000/json_rpc 2>/dev/null || true)"
        if grep -qi '^www-authenticate: *digest' <<< "${headers//$'\r'/}"; then
            err "nginx 127.0.0.1:23000 (the public BTCPay listener) reaches the wallet RPC for Host ${host}; refusing."
            exit 1
        fi
    done
    info "Wallet RPC is reachable through nginx only on 127.0.0.1:23001."
}

print_summary() {
    local creds_file="${MONERO_DIR}/monero_rpc_auth.env"
    local rpc_user="winsmonero"
    if [[ -f "${creds_file}" ]]; then
        # shellcheck disable=SC1090
        source "${creds_file}"
        rpc_user="${MONERO_WALLET_RPC_USER:-winsmonero}"
    fi

    printf '\n====================================================================\n'
    printf 'WIN'\''S VPN SPAIN SERVER CRYPTO PAYMENTS SETUP COMPLETE\n'
    printf '====================================================================\n'
    printf 'Host: Spain Madrid (NODE_IP_ES1)\n'
    printf 'BTCPay Server Domain: btcpay.winsvpn.org\n'
    printf 'BTCPay Local Upstream: http://127.0.0.1:49392\n'
    printf 'Monero RPC Local Endpoint: http://127.0.0.1:18083 (loopback only)\n'
    printf 'BTCPay Proxy Port: http://127.0.0.1:23000 (tunnel ingress for btcpay.winsvpn.org)\n'
    printf 'Wallet RPC Proxy Port: http://127.0.0.1:23001 (tunnel ingress for monero-rpc.winsvpn.org only)\n'
    # Fleet reset TP-P5: never a hand edit of the hub runtime file.
    printf '\nKansas Hub commerce secrets. Append to root-owned /root/winsvpn-secrets.env\n'
    printf '(never edit /root/vpn_auth.env by hand). The BTCPay keys take effect with\n'
    printf '  sudo bash wins_control_plane_setup_ONETOUCH.sh --apply-commerce-secrets\n'
    printf 'which does not apply the Monero keys; those take effect on the next --deploy.\n'
    printf '--------------------------------------------------------------------\n'
    printf 'BTCPAY_URL="https://btcpay.winsvpn.org"\n'
    printf 'BTCPAY_STORE_ID="<create store in BTCPay UI and paste ID here>"\n'
    printf 'BTCPAY_API_KEY="<generate Greenfield API key and paste here>"\n'
    printf 'BTCPAY_WEBHOOK_SECRET="<secret of the store webhook whose URL is https://sync.winsvpn.org/webhook/btcpay, events InvoiceSettled and InvoicePaymentSettled>"\n'
    printf 'MONERO_WALLET_RPC_URL="https://monero-rpc.winsvpn.org"\n'
    printf '# In /root/winsvpn-defaults.env, once the Access application guards monero-rpc:\n'
    printf '# MONERO_WALLET_RPC_CF_ACCESS=1\n'
    printf '# and, in /root/winsvpn-secrets.env, the OWN service token of that Access\n'
    printf '# application (never the management token winsvpn-management-hub):\n'
    printf '# MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID="<client id>.access"\n'
    printf '# MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET="<client secret>"\n'
    printf 'MONERO_WALLET_RPC_USER="%s"\n' "${rpc_user}"
    printf 'MONERO_WALLET_RPC_PASS is stored in %s and is not printed\n' "${creds_file}"
    printf '====================================================================\n\n'
}

main() {
    require_root
    require_dependencies
    setup_directories
    setup_monero_service
    setup_btcpay_server
    setup_nginx_proxy
    verify_services
    print_summary
}

main "$@"
