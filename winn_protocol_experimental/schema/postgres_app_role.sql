-- Run after schema/postgres_v1.sql as a PostgreSQL owner/administrator.
-- Replace winn_runtime with the deployment's NOLOGIN group role as needed.

GRANT CONNECT ON DATABASE winn TO winn_runtime;
GRANT USAGE ON SCHEMA public TO winn_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE
    winn_schema,
    winn_revoked_devices,
    winn_peers,
    winn_requests,
    winn_privacy_token_redemptions
TO winn_runtime;
