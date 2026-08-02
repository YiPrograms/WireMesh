PRAGMA foreign_keys = ON;

CREATE TABLE system_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    creator_kind TEXT NOT NULL CHECK (creator_kind IN ('local', 'oidc', 'ldap')),
    manual_disabled INTEGER NOT NULL DEFAULT 0,
    ldap_disabled INTEGER NOT NULL DEFAULT 0,
    device_limit_override INTEGER,
    soft_deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE identity_providers (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('oidc', 'ldap')),
    name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    trusted_create INTEGER NOT NULL DEFAULT 0,
    sync_interval_seconds INTEGER,
    config_envelope BLOB NOT NULL,
    last_successful_sync_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE user_identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    provider_id TEXT REFERENCES identity_providers(id),
    kind TEXT NOT NULL CHECK (kind IN ('local', 'oidc', 'ldap')),
    external_id TEXT NOT NULL,
    current_email TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}',
    active INTEGER NOT NULL DEFAULT 1,
    provider_enabled INTEGER NOT NULL DEFAULT 1,
    last_seen_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider_id, external_id)
);

CREATE INDEX user_identities_user_idx ON user_identities(user_id);

CREATE TABLE local_passwords (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    password_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    credential_id BLOB NOT NULL UNIQUE,
    public_key_cose BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE groups (
    id TEXT PRIMARY KEY,
    normalized_name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE group_memberships (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES groups(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('local', 'oidc', 'ldap')),
    source_id TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    UNIQUE(group_id, user_id, source_kind, source_id)
);

CREATE INDEX memberships_user_idx ON group_memberships(user_id, active);

CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('linux', 'mikrotik')),
    current_secret_hash BLOB NOT NULL,
    next_secret_hash BLOB,
    protocol_major INTEGER,
    protocol_minor INTEGER,
    version TEXT,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    boot_id TEXT,
    last_seen_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sites (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    acl_default TEXT NOT NULL DEFAULT 'allow' CHECK (acl_default IN ('allow', 'deny')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE gateways (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL UNIQUE REFERENCES sites(id),
    agent_id TEXT REFERENCES agents(id),
    kind TEXT NOT NULL CHECK (kind IN ('linux', 'mikrotik')),
    status TEXT NOT NULL DEFAULT 'provisioning',
    interface_name TEXT NOT NULL,
    endpoint_host TEXT NOT NULL,
    public_port INTEGER,
    listen_port INTEGER,
    public_key TEXT,
    router_url TEXT,
    router_credential_envelope BLOB,
    router_certificate_pin TEXT,
    compatibility_address INTEGER NOT NULL DEFAULT 0,
    desired_revision INTEGER NOT NULL DEFAULT 0,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    actual_state_hash TEXT,
    last_seen_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE site_routes (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(id),
    cidr TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(site_id, cidr)
);

CREATE TABLE site_grants (
    site_id TEXT NOT NULL REFERENCES sites(id),
    group_id TEXT NOT NULL REFERENCES groups(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(site_id, group_id)
);

CREATE TABLE acl_rules (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(id),
    position INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
    destination TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('any', 'tcp', 'udp', 'icmp')),
    port_start INTEGER,
    port_end INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(site_id, position)
);

CREATE TABLE acl_rule_users (
    rule_id TEXT NOT NULL REFERENCES acl_rules(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY(rule_id, user_id)
);

CREATE TABLE acl_rule_groups (
    rule_id TEXT NOT NULL REFERENCES acl_rules(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id),
    PRIMARY KEY(rule_id, group_id)
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    vpn_address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'deleted')),
    config_revision INTEGER NOT NULL DEFAULT 1,
    acknowledged_revision INTEGER NOT NULL DEFAULT 0,
    acknowledgement_method TEXT,
    acknowledged_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    UNIQUE(user_id, name)
);

CREATE INDEX devices_user_idx ON devices(user_id, status);

CREATE TABLE key_registry (
    id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('device', 'gateway')),
    owner_id TEXT NOT NULL,
    activated_at TEXT NOT NULL,
    retired_at TEXT
);

CREATE UNIQUE INDEX key_registry_active_unique
    ON key_registry(public_key) WHERE retired_at IS NULL;

CREATE TABLE ip_leases (
    id TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    allocated_at TEXT NOT NULL,
    quarantined_at TEXT,
    released_at TEXT
);

CREATE UNIQUE INDEX ip_leases_live_unique
    ON ip_leases(address) WHERE released_at IS NULL;

CREATE TABLE lease_gateway_acks (
    lease_id TEXT NOT NULL REFERENCES ip_leases(id),
    gateway_id TEXT NOT NULL REFERENCES gateways(id),
    required_revision INTEGER NOT NULL,
    acknowledged_at TEXT,
    PRIMARY KEY(lease_id, gateway_id)
);

CREATE TABLE config_snapshots (
    device_id TEXT NOT NULL REFERENCES devices(id),
    revision INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    model_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(device_id, revision)
);

CREATE TABLE gateway_desired_states (
    gateway_id TEXT NOT NULL REFERENCES gateways(id),
    revision INTEGER NOT NULL,
    state_json TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(gateway_id, revision)
);

CREATE TABLE gateway_apply_events (
    id TEXT PRIMARY KEY,
    gateway_id TEXT NOT NULL REFERENCES gateways(id),
    revision INTEGER NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('prepared', 'applied', 'error')),
    state_hash TEXT,
    error_code TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE subnet_migrations (
    id TEXT PRIMARY KEY,
    old_pool TEXT NOT NULL,
    new_pool TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('preparing', 'armed', 'cancelled', 'applied', 'failed')),
    plan_json TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE one_time_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    purpose TEXT NOT NULL CHECK (purpose IN ('enrollment', 'reset')),
    token_hash BLOB NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash BLOB NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE mail_jobs (
    id TEXT PRIMARY KEY,
    recipient TEXT NOT NULL,
    template TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    actor_user_id TEXT,
    actor_kind TEXT NOT NULL,
    action TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    object_id TEXT,
    outcome TEXT NOT NULL,
    remote_address TEXT,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_occurred_idx ON audit_events(occurred_at DESC);

INSERT INTO system_settings(key, value_json, updated_at)
VALUES
    ('client_pool', '"10.20.0.0/16"', datetime('now')),
    ('default_device_limit', '5', datetime('now')),
    ('client_options', '{"dns_servers":[],"search_domains":[],"mtu":null,"persistent_keepalive":25}', datetime('now'));

