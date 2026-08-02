CREATE TABLE subnet_migration_gateways (
    migration_id TEXT NOT NULL REFERENCES subnet_migrations(id),
    gateway_id TEXT NOT NULL REFERENCES gateways(id),
    base_revision INTEGER NOT NULL,
    future_revision INTEGER NOT NULL,
    expected_state_hash TEXT NOT NULL,
    prepared_state_hash TEXT,
    prepared_at TEXT,
    PRIMARY KEY(migration_id, gateway_id)
);

CREATE INDEX subnet_migration_status_idx
    ON subnet_migrations(status, effective_at);
