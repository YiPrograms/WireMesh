-- Keep authorization semantics in one place so disabled providers and stale
-- OIDC claims cannot grant access. Local memberships are always effective.
-- LDAP takes precedence over OIDC as soon as a user has any linked LDAP
-- identity, while memberships from disabled providers are ignored.
CREATE VIEW effective_group_memberships AS
SELECT gm.id, gm.group_id, gm.user_id, gm.source_kind, gm.source_id,
       gm.active, gm.updated_at
FROM group_memberships gm
WHERE gm.active = 1
  AND (
    gm.source_kind = 'local'
    OR (
      gm.source_kind = 'ldap'
      AND EXISTS (
        SELECT 1 FROM identity_providers p
        WHERE p.id = gm.source_id AND p.kind = 'ldap' AND p.enabled = 1
      )
    )
    OR (
      gm.source_kind = 'oidc'
      AND NOT EXISTS (
        SELECT 1 FROM user_identities ui
        WHERE ui.user_id = gm.user_id AND ui.kind = 'ldap'
      )
      AND EXISTS (
        SELECT 1 FROM identity_providers p
        WHERE p.id = gm.source_id AND p.kind = 'oidc' AND p.enabled = 1
      )
    )
  );

-- A lease timestamp lets the durable SMTP worker recover a job when the
-- controller exits after claiming it but before recording the result.
ALTER TABLE mail_jobs ADD COLUMN claimed_at TEXT;

-- Audit history is append-only even for direct SQL users. SQLite migrations
-- and backups remain possible because schema changes do not update/delete rows.
CREATE TRIGGER audit_events_reject_update
BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER audit_events_reject_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit events are append-only');
END;
