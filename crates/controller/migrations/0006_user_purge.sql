ALTER TABLE users ADD COLUMN purged_at TEXT;

CREATE TABLE user_deletion_gateway_acks (
    user_id TEXT NOT NULL REFERENCES users(id),
    gateway_id TEXT NOT NULL REFERENCES gateways(id),
    required_revision INTEGER NOT NULL,
    acknowledged_at TEXT,
    PRIMARY KEY(user_id, gateway_id)
);

