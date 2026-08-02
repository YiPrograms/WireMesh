CREATE TABLE identity_sync_runs (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES identity_providers(id),
    status TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed', 'partial')),
    seen_entries INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX identity_sync_provider_idx
    ON identity_sync_runs(provider_id, started_at DESC);

CREATE TABLE oidc_login_states (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES identity_providers(id),
    state_hash BLOB NOT NULL UNIQUE,
    nonce_hash BLOB NOT NULL,
    pkce_verifier_envelope BLOB NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
