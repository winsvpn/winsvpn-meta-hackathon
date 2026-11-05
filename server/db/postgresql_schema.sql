-- Win's VPN Control Hub PostgreSQL Production Schema
-- Designed for high concurrency, zero lock contention, and millions of active users.
-- Replaces legacy SQLite single-writer database (vpn_users.db).

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users and Account Management
CREATE TABLE IF NOT EXISTS users (
    account_number VARCHAR(64) PRIMARY KEY,
    email VARCHAR(254),
    subscriber_name VARCHAR(255) DEFAULT 'Wins VPN User',
    status VARCHAR(32) DEFAULT 'active',
    expiration_date TIMESTAMPTZ,
    hardware_hash VARCHAR(128),
    paypal_subscription_id VARCHAR(128),
    paypal_plan_id VARCHAR(128),
    paypal_payer_id VARCHAR(128),
    paypal_status VARCHAR(64),
    paypal_purchase_reference VARCHAR(128),
    last_paypal_sync TIMESTAMPTZ,
    renewal_source VARCHAR(64),
    referral_code VARCHAR(64) UNIQUE,
    referred_by_account_number VARCHAR(64),
    referral_bonus_days INTEGER DEFAULT 0,
    referral_bonus_applied_at TIMESTAMPTZ,
    activation_secret_hash VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_expiration ON users(expiration_date);
CREATE INDEX IF NOT EXISTS idx_users_paypal_sub ON users(paypal_subscription_id);
CREATE INDEX IF NOT EXISTS idx_users_referral ON users(referral_code);

-- User Devices and Tunnel Sessions
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(64) PRIMARY KEY,
    account_number VARCHAR(64) NOT NULL REFERENCES users(account_number) ON DELETE CASCADE,
    device_model VARCHAR(255) DEFAULT 'Unknown Device',
    hardware_hash VARCHAR(128),
    source_ip_bucket VARCHAR(64),
    vpn_internal_ip INET UNIQUE,
    client_private_key VARCHAR(128),
    client_public_key VARCHAR(128),
    preshared_key VARCHAR(128),
    last_seen TIMESTAMPTZ,
    location_slug VARCHAR(64),
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    device_auth_token_hash VARCHAR(128),
    winn3_inner_v4 INET,
    winn3_static_private VARCHAR(128),
    winn3_static_public VARCHAR(128)
);

CREATE INDEX IF NOT EXISTS idx_devices_account ON devices(account_number);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(device_auth_token_hash);
CREATE INDEX IF NOT EXISTS idx_devices_winn3_public ON devices(winn3_static_public);

-- VPN Gateways and Dataplane Nodes
CREATE TABLE IF NOT EXISTS nodes (
    slug VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255),
    flag VARCHAR(16),
    endpoint VARCHAR(255),
    tunnel_gateway_ipv4 INET,
    stealth_endpoint VARCHAR(255),
    public_key VARCHAR(128),
    preshared_key VARCHAR(128),
    status VARCHAR(32) DEFAULT 'online',
    last_heartbeat TIMESTAMPTZ,
    obfuscation_json JSONB,
    protocol_version VARCHAR(32) DEFAULT 'winn/3',
    protocol_params_json JSONB,
    data_plane_code_revision VARCHAR(128),
    ssh_host VARCHAR(255),
    wg_port INTEGER DEFAULT 9110,
    xray_uuid UUID,
    xray_path VARCHAR(255) DEFAULT '/wins-stealth-tunnel',
    xray_security VARCHAR(32) DEFAULT 'none',
    xray_sni VARCHAR(255),
    stealth_public_port INTEGER DEFAULT 80,
    xray_inbound_port INTEGER DEFAULT 10085,
    regional_aliases JSONB DEFAULT '[]'::jsonb,
    stealth_transports JSONB DEFAULT '[]'::jsonb,
    awg_rx_bytes BIGINT DEFAULT 0,
    awg_tx_bytes BIGINT DEFAULT 0,
    wan_rx_bytes BIGINT DEFAULT 0,
    wan_tx_bytes BIGINT DEFAULT 0,
    rx_mbps NUMERIC(10, 2) DEFAULT 0,
    tx_mbps NUMERIC(10, 2) DEFAULT 0,
    peer_count INTEGER DEFAULT 0,
    max_peers INTEGER DEFAULT 0,
    free_access_enabled BOOLEAN DEFAULT FALSE,
    direct_awg_enabled BOOLEAN DEFAULT TRUE,
    operator_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    management_status VARCHAR(64) DEFAULT 'unknown',
    management_checked_at TIMESTAMPTZ,
    management_error TEXT,
    winn3_canary_status VARCHAR(64) DEFAULT 'unknown',
    winn3_canary_checked_at TIMESTAMPTZ,
    winn3_canary_ok_at TIMESTAMPTZ,
    winn3_canary_error TEXT DEFAULT '',
    node_token_hash VARCHAR(128),
    retired_at TIMESTAMPTZ,
    deployment_withdrawal_id VARCHAR(128),
    deployment_withdrawn_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_nodes_operator ON nodes(operator_enabled);
CREATE INDEX IF NOT EXISTS idx_nodes_winn3_canary ON nodes(winn3_canary_status);

-- Node Retirements and Audit Events
CREATE TABLE IF NOT EXISTS node_retirements (
    id BIGSERIAL PRIMARY KEY,
    slug VARCHAR(64) NOT NULL,
    retired_at TIMESTAMPTZ NOT NULL,
    reason TEXT,
    recorded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS node_promotion_events (
    id BIGSERIAL PRIMARY KEY,
    slug VARCHAR(64) NOT NULL,
    prior_status VARCHAR(64),
    new_status VARCHAR(64),
    promoted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS core_servers (
    core_id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255),
    ip_address INET,
    public_key VARCHAR(128),
    status VARCHAR(32) DEFAULT 'online',
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS bootstrap_grants (
    id BIGSERIAL PRIMARY KEY,
    grant_token VARCHAR(128) UNIQUE NOT NULL,
    account_number VARCHAR(64) REFERENCES users(account_number) ON DELETE CASCADE,
    device_id VARCHAR(64),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS double_vpn_assignments (
    id BIGSERIAL PRIMARY KEY,
    account_number VARCHAR(64) REFERENCES users(account_number) ON DELETE CASCADE,
    entry_node_slug VARCHAR(64) REFERENCES nodes(slug),
    exit_node_slug VARCHAR(64) REFERENCES nodes(slug),
    assigned_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(128) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Payment & Commerce Tables
CREATE TABLE IF NOT EXISTS paypal_events (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(128) UNIQUE NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64),
    summary TEXT,
    payload JSONB,
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS monero_orders (
    id BIGSERIAL PRIMARY KEY,
    order_id VARCHAR(64) UNIQUE NOT NULL,
    account_number VARCHAR(64),
    plan_key VARCHAR(64) NOT NULL,
    amount_xmr NUMERIC(18, 12) NOT NULL,
    recipient_address VARCHAR(128) NOT NULL,
    payment_id VARCHAR(64),
    email VARCHAR(254),
    status VARCHAR(32) DEFAULT 'pending',
    tx_hash VARCHAR(128),
    confirmations INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_monero_orders_status ON monero_orders(status);
CREATE INDEX IF NOT EXISTS idx_monero_orders_addr ON monero_orders(recipient_address);

CREATE TABLE IF NOT EXISTS payment_orders (
    id BIGSERIAL PRIMARY KEY,
    order_reference VARCHAR(128) UNIQUE NOT NULL,
    provider VARCHAR(32) NOT NULL,
    plan_key VARCHAR(64) NOT NULL,
    amount_usd NUMERIC(10, 2),
    currency VARCHAR(16) DEFAULT 'USD',
    account_number VARCHAR(64),
    email VARCHAR(254),
    status VARCHAR(32) DEFAULT 'pending',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status);

CREATE TABLE IF NOT EXISTS payment_order_archive (
    id BIGSERIAL PRIMARY KEY,
    order_reference VARCHAR(128) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    plan_key VARCHAR(64) NOT NULL,
    account_number VARCHAR(64),
    status VARCHAR(32),
    finalized_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    archive_data JSONB
);

-- Rate Limiting (High-Throughput In-Memory / Unlogged Option for Scale)
CREATE UNLOGGED TABLE IF NOT EXISTS rate_limits (
    bucket VARCHAR(128) NOT NULL,
    window_start BIGINT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (bucket, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);

-- Security Events & Audit
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    event_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    source_ip INET,
    event_type VARCHAR(64) NOT NULL,
    severity INTEGER DEFAULT 1,
    signature_id VARCHAR(64),
    details JSONB
);

CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(event_time);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(source_ip);

-- Legal Compliance & Acceptance
CREATE TABLE IF NOT EXISTS legal_documents (
    version VARCHAR(64) PRIMARY KEY,
    effective_date DATE NOT NULL,
    content_hash VARCHAR(128) NOT NULL,
    title VARCHAR(255) NOT NULL,
    document_text TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS legal_acceptances (
    id BIGSERIAL PRIMARY KEY,
    account_number VARCHAR(64) REFERENCES users(account_number) ON DELETE CASCADE,
    device_id VARCHAR(64),
    document_version VARCHAR(64) REFERENCES legal_documents(version),
    ip_bucket VARCHAR(64),
    accepted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_legal_acceptances_account ON legal_acceptances(account_number);

-- Account Deletion Queue & Audit
CREATE TABLE IF NOT EXISTS account_deletion_requests (
    id BIGSERIAL PRIMARY KEY,
    account_number VARCHAR(64) NOT NULL,
    confirmation_token VARCHAR(128) UNIQUE NOT NULL,
    status VARCHAR(32) DEFAULT 'pending',
    requested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    executed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS account_deletion_audit (
    id BIGSERIAL PRIMARY KEY,
    account_number_hash VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    devices_purged INTEGER DEFAULT 0,
    sessions_purged INTEGER DEFAULT 0
);
