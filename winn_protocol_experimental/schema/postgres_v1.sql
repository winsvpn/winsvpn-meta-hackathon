BEGIN;

SELECT pg_advisory_xact_lock(7829892146624602157);

CREATE TABLE IF NOT EXISTS winn_schema (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version integer NOT NULL
);

INSERT INTO winn_schema (singleton, version)
VALUES (true, 1)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS winn_revoked_devices (
    controller_id text NOT NULL,
    device_id text NOT NULL,
    revoked boolean NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (controller_id, device_id)
);

CREATE TABLE IF NOT EXISTS winn_peers (
    controller_id text NOT NULL,
    device_id text NOT NULL,
    peer_public_key text NOT NULL,
    suite text NOT NULL,
    generation bigint NOT NULL CHECK (generation >= 0),
    key_id text NOT NULL,
    issued_at timestamptz,
    expires_at timestamptz,
    pending_request_id text,
    PRIMARY KEY (controller_id, device_id, peer_public_key)
);

CREATE TABLE IF NOT EXISTS winn_requests (
    controller_id text NOT NULL,
    request_id text NOT NULL,
    device_id text NOT NULL,
    peer_public_key text NOT NULL,
    digest text NOT NULL CHECK (length(digest) = 64),
    response_envelope bytea NOT NULL,
    created_at timestamptz NOT NULL,
    committed boolean NOT NULL DEFAULT false,
    PRIMARY KEY (controller_id, request_id)
);

CREATE INDEX IF NOT EXISTS winn_requests_retention_idx
ON winn_requests (created_at)
WHERE committed = true;

CREATE TABLE IF NOT EXISTS winn_privacy_token_redemptions (
    token_id text PRIMARY KEY CHECK (length(token_id) = 64),
    expires_at timestamptz NOT NULL,
    redeemed_at timestamptz NOT NULL,
    CHECK (expires_at > redeemed_at)
);

CREATE INDEX IF NOT EXISTS winn_privacy_token_redemptions_expiry_idx
ON winn_privacy_token_redemptions (expires_at);

DO $migration$
DECLARE
    installed_version integer;
BEGIN
    SELECT version INTO installed_version
    FROM winn_schema
    WHERE singleton = true;

    IF installed_version <> 1 THEN
        RAISE EXCEPTION 'unsupported Winn schema version %', installed_version;
    END IF;
END
$migration$;

COMMIT;
