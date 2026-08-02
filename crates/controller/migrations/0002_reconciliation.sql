CREATE TABLE key_gateway_acks (
    key_id TEXT NOT NULL REFERENCES key_registry(id),
    gateway_id TEXT NOT NULL REFERENCES gateways(id),
    required_revision INTEGER NOT NULL,
    acknowledged_at TEXT,
    PRIMARY KEY(key_id, gateway_id)
);

CREATE INDEX gateway_apply_events_gateway_idx
    ON gateway_apply_events(gateway_id, revision DESC);

CREATE INDEX sessions_expiry_idx ON sessions(expires_at);
CREATE INDEX one_time_tokens_expiry_idx ON one_time_tokens(expires_at);

INSERT INTO system_settings(key, value_json, updated_at)
VALUES ('session_lifetime_seconds', '43200', datetime('now'));
