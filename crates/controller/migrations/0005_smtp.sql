CREATE TABLE smtp_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    config_envelope BLOB NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX mail_jobs_due_idx
    ON mail_jobs(status, next_attempt_at, created_at);

