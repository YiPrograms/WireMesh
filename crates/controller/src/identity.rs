use std::collections::BTreeSet;

use chrono::Utc;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use crate::{
    desired,
    error::ApiError,
    models::{
        CreateProviderRequest, LdapSnapshotEntry, LdapSyncSnapshot, OidcClaims, ProviderKind,
        ProviderResponse, UserResponse,
    },
    secrets::SecretBox,
    service,
};

pub async fn create_provider(
    pool: &SqlitePool,
    secrets: &SecretBox,
    request: CreateProviderRequest,
) -> Result<ProviderResponse, ApiError> {
    validate_provider_config(request.kind, request.sync_interval_seconds, &request.config)?;
    let name = request.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(ApiError::Validation(
            "provider name must contain 1-128 characters".into(),
        ));
    }
    let id = Uuid::now_v7();
    let context = format!("identity-provider:{id}");
    let envelope = secrets
        .encrypt(&context, &request.config)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let timestamp = Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO identity_providers(id,kind,name,enabled,priority,trusted_create,sync_interval_seconds,config_envelope,created_at,updated_at)
         VALUES(?,?,?,1,100,?,?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(request.kind.as_str())
    .bind(name)
    .bind(request.trusted_create)
    .bind(request.sync_interval_seconds.map(i64::from))
    .bind(envelope)
    .bind(&timestamp)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = result {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            return Err(ApiError::Conflict("provider name already exists".into()));
        }
        return Err(error.into());
    }
    insert_audit(
        &mut transaction,
        "identity.provider.create",
        "identity_provider",
        Some(id),
        serde_json::json!({"kind": request.kind.as_str(), "name": name}),
    )
    .await?;
    transaction.commit().await?;
    get_provider(pool, id).await
}

pub async fn list_providers(pool: &SqlitePool) -> Result<Vec<ProviderResponse>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,kind,name,enabled,trusted_create,sync_interval_seconds,last_successful_sync_at
         FROM identity_providers ORDER BY priority,name",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(provider_from_row).collect()
}

pub async fn get_provider(
    pool: &SqlitePool,
    provider_id: Uuid,
) -> Result<ProviderResponse, ApiError> {
    let row = sqlx::query(
        "SELECT id,kind,name,enabled,trusted_create,sync_interval_seconds,last_successful_sync_at
         FROM identity_providers WHERE id=?",
    )
    .bind(provider_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("identity provider does not exist".into()))?;
    provider_from_row(row)
}

pub async fn provider_config(
    pool: &SqlitePool,
    secrets: &SecretBox,
    provider_id: Uuid,
) -> Result<serde_json::Value, ApiError> {
    let envelope: Vec<u8> =
        sqlx::query_scalar("SELECT config_envelope FROM identity_providers WHERE id=?")
            .bind(provider_id.to_string())
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| ApiError::NotFound("identity provider does not exist".into()))?;
    secrets
        .decrypt(&format!("identity-provider:{provider_id}"), &envelope)
        .map_err(|error| ApiError::Internal(error.into()))
}

pub async fn set_provider_enabled(
    pool: &SqlitePool,
    provider_id: Uuid,
    enabled: bool,
) -> Result<ProviderResponse, ApiError> {
    let mut transaction = pool.begin().await?;
    let result = sqlx::query("UPDATE identity_providers SET enabled=?,updated_at=? WHERE id=?")
        .bind(enabled)
        .bind(Utc::now().to_rfc3339())
        .bind(provider_id.to_string())
        .execute(&mut *transaction)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("identity provider does not exist".into()));
    }
    sqlx::query("UPDATE user_identities SET provider_enabled=?,updated_at=? WHERE provider_id=?")
        .bind(enabled)
        .bind(Utc::now().to_rfc3339())
        .bind(provider_id.to_string())
        .execute(&mut *transaction)
        .await?;
    recompute_ldap_disablement(&mut transaction).await?;
    service::ensure_enabled_admin_exists(&mut transaction).await?;
    let terminate = service::all_active_addresses(&mut transaction).await?;
    service::refresh_all_client_configs(&mut transaction).await?;
    desired::rebuild_all_gateways(&mut transaction, terminate).await?;
    insert_audit(
        &mut transaction,
        "identity.provider.enabled",
        "identity_provider",
        Some(provider_id),
        serde_json::json!({"enabled": enabled}),
    )
    .await?;
    transaction.commit().await?;
    get_provider(pool, provider_id).await
}

pub async fn apply_ldap_snapshot(
    pool: &SqlitePool,
    provider_id: Uuid,
    snapshot: LdapSyncSnapshot,
) -> Result<(), ApiError> {
    let provider = get_provider(pool, provider_id).await?;
    if !matches!(provider.kind, ProviderKind::Ldap) {
        return Err(ApiError::Validation("provider is not LDAP".into()));
    }
    let run_id = Uuid::now_v7();
    let started_at = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO identity_sync_runs(id,provider_id,status,seen_entries,started_at) VALUES(?,?,?,?,?)",
    )
    .bind(run_id.to_string())
    .bind(provider_id.to_string())
    .bind(if snapshot.complete { "running" } else { "partial" })
    .bind(snapshot.entries.len() as i64)
    .bind(&started_at)
    .execute(pool)
    .await?;
    if !snapshot.complete {
        sqlx::query(
            "UPDATE identity_sync_runs SET error_message=?,completed_at=? WHERE id=?",
        )
        .bind("partial LDAP results were discarded")
        .bind(Utc::now().to_rfc3339())
        .bind(run_id.to_string())
        .execute(pool)
        .await?;
        return Err(ApiError::Validation(
            "LDAP sync was partial; existing identity state was preserved".into(),
        ));
    }
    let entries = validate_ldap_entries(snapshot.entries)?;
    let mut transaction = pool.begin().await?;
    let existing_users = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT user_id FROM user_identities WHERE provider_id=?",
    )
    .bind(provider_id.to_string())
    .fetch_all(&mut *transaction)
    .await?;
    let mut affected = existing_users
        .into_iter()
        .map(|value| parse_uuid(&value, "user"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    sqlx::query("UPDATE user_identities SET active=0,updated_at=? WHERE provider_id=?")
        .bind(Utc::now().to_rfc3339())
        .bind(provider_id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE group_memberships SET active=0,updated_at=? WHERE source_kind='ldap' AND source_id=?",
    )
    .bind(Utc::now().to_rfc3339())
    .bind(provider_id.to_string())
    .execute(&mut *transaction)
    .await?;

    for entry in entries {
        let user_id = link_or_create_user(
            &mut transaction,
            provider_id,
            "ldap",
            &entry.external_id,
            &entry.email,
            &entry.name,
            &entry.title,
            true,
        )
        .await?;
        affected.insert(user_id);
        sqlx::query(
            "UPDATE user_identities SET current_email=?,attributes_json=?,active=?,provider_enabled=?,last_seen_at=?,updated_at=?
             WHERE provider_id=? AND external_id=?",
        )
        .bind(&entry.email)
        .bind(serde_json::json!({"name": entry.name, "title": entry.title}).to_string())
        .bind(entry.active)
        .bind(provider.enabled)
        .bind(Utc::now().to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .bind(provider_id.to_string())
        .bind(&entry.external_id)
        .execute(&mut *transaction)
        .await?;
        for group in entry.groups {
            let group_id = upsert_group(&mut transaction, &group).await?;
            upsert_membership(
                &mut transaction,
                group_id,
                user_id,
                "ldap",
                &provider_id.to_string(),
                entry.active,
            )
            .await?;
        }
    }
    recompute_ldap_disablement(&mut transaction).await?;
    service::ensure_enabled_admin_exists(&mut transaction).await?;
    for user_id in affected {
        service::refresh_user_configs(&mut transaction, user_id).await?;
    }
    let terminate = service::all_active_addresses(&mut transaction).await?;
    desired::rebuild_all_gateways(&mut transaction, terminate).await?;
    let completed_at = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE identity_sync_runs SET status='success',completed_at=? WHERE id=?",
    )
    .bind(&completed_at)
    .bind(run_id.to_string())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE identity_providers SET last_successful_sync_at=?,updated_at=? WHERE id=?",
    )
    .bind(&completed_at)
    .bind(&completed_at)
    .bind(provider_id.to_string())
    .execute(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        "identity.ldap.sync",
        "identity_provider",
        Some(provider_id),
        serde_json::json!({"run_id": run_id}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

/// Applies claims only after the OIDC adapter has verified issuer, signature,
/// audience, nonce, expiry, and PKCE. This function enforces WireMesh's linking
/// and source-precedence semantics.
pub async fn apply_verified_oidc_claims(
    pool: &SqlitePool,
    provider_id: Uuid,
    claims: OidcClaims,
) -> Result<UserResponse, ApiError> {
    if !claims.email_verified {
        return Err(ApiError::Forbidden(
            "OIDC provider did not verify the email claim".into(),
        ));
    }
    if claims.subject.trim().is_empty() {
        return Err(ApiError::Validation("OIDC subject is required".into()));
    }
    let provider = get_provider(pool, provider_id).await?;
    if !matches!(provider.kind, ProviderKind::Oidc) || !provider.enabled {
        return Err(ApiError::Forbidden("OIDC provider is not enabled".into()));
    }
    let email = wiremesh_domain::normalize_email(&claims.email)?;
    let groups = claims
        .groups
        .iter()
        .map(|group| wiremesh_domain::normalize_group_name(group))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut transaction = pool.begin().await?;
    let user_id = link_or_create_user(
        &mut transaction,
        provider_id,
        "oidc",
        claims.subject.trim(),
        &email,
        &claims.name,
        &claims.title,
        provider.trusted_create,
    )
    .await?;
    let terminate = service::active_addresses_for_user(&mut transaction, user_id).await?;
    sqlx::query(
        "UPDATE user_identities SET current_email=?,attributes_json=?,active=1,provider_enabled=1,last_seen_at=?,updated_at=?
         WHERE provider_id=? AND external_id=?",
    )
    .bind(&email)
    .bind(serde_json::json!({"name": claims.name, "title": claims.title}).to_string())
    .bind(Utc::now().to_rfc3339())
    .bind(Utc::now().to_rfc3339())
    .bind(provider_id.to_string())
    .bind(claims.subject.trim())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE group_memberships SET active=0,updated_at=? WHERE source_kind='oidc' AND source_id=? AND user_id=?",
    )
    .bind(Utc::now().to_rfc3339())
    .bind(provider_id.to_string())
    .bind(user_id.to_string())
    .execute(&mut *transaction)
    .await?;
    for group in groups {
        let group_id = upsert_group(&mut transaction, &group).await?;
        upsert_membership(
            &mut transaction,
            group_id,
            user_id,
            "oidc",
            &provider_id.to_string(),
            true,
        )
        .await?;
    }
    recompute_ldap_disablement(&mut transaction).await?;
    service::ensure_enabled_admin_exists(&mut transaction).await?;
    service::refresh_user_configs(&mut transaction, user_id).await?;
    desired::rebuild_all_gateways(&mut transaction, terminate).await?;
    insert_audit(
        &mut transaction,
        "auth.login.oidc",
        "user",
        Some(user_id),
        serde_json::json!({"provider_id": provider_id}),
    )
    .await?;
    transaction.commit().await?;
    service::get_user(pool, user_id).await
}

async fn link_or_create_user(
    transaction: &mut Transaction<'_, Sqlite>,
    provider_id: Uuid,
    kind: &str,
    external_id: &str,
    email: &str,
    name: &str,
    title: &str,
    may_create: bool,
) -> Result<Uuid, ApiError> {
    if let Some(user_id) = sqlx::query_scalar::<_, String>(
        "SELECT user_id FROM user_identities WHERE provider_id=? AND external_id=?",
    )
    .bind(provider_id.to_string())
    .bind(external_id)
    .fetch_optional(&mut **transaction)
    .await?
    {
        return parse_uuid(&user_id, "user");
    }
    let email = wiremesh_domain::normalize_email(email)?;
    let user_id = match sqlx::query(
        "SELECT id,soft_deleted_at FROM users WHERE email=?",
    )
    .bind(&email)
    .fetch_optional(&mut **transaction)
    .await?
    {
        Some(row) => {
            if row.try_get::<Option<String>, _>("soft_deleted_at")?.is_some() {
                return Err(ApiError::Conflict(
                    "email belongs to a soft-deleted user".into(),
                ));
            }
            parse_uuid(&row.try_get::<String, _>("id")?, "user")?
        }
        None if may_create => {
            if name.trim().is_empty() {
                return Err(ApiError::Validation("identity name is required".into()));
            }
            let id = Uuid::now_v7();
            let timestamp = Utc::now().to_rfc3339();
            sqlx::query(
                "INSERT INTO users(id,email,name,title,creator_kind,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            )
            .bind(id.to_string())
            .bind(&email)
            .bind(name.trim())
            .bind(title.trim())
            .bind(kind)
            .bind(&timestamp)
            .bind(&timestamp)
            .execute(&mut **transaction)
            .await?;
            id
        }
        None => {
            return Err(ApiError::Forbidden(
                "provider is link-only and no user has this email".into(),
            ));
        }
    };
    let timestamp = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO user_identities(id,user_id,provider_id,kind,external_id,current_email,active,provider_enabled,created_at,updated_at)
         VALUES(?,?,?,?,?,?,1,1,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(user_id.to_string())
    .bind(provider_id.to_string())
    .bind(kind)
    .bind(external_id)
    .bind(&email)
    .bind(&timestamp)
    .bind(&timestamp)
    .execute(&mut **transaction)
    .await?;
    Ok(user_id)
}

async fn recompute_ldap_disablement(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE users SET ldap_disabled=(
           EXISTS(SELECT 1 FROM user_identities linked WHERE linked.user_id=users.id AND linked.kind='ldap')
           AND NOT EXISTS(
             SELECT 1 FROM user_identities active
             JOIN identity_providers p ON p.id=active.provider_id
             WHERE active.user_id=users.id AND active.kind='ldap' AND active.active=1 AND p.enabled=1
           )
         ),updated_at=?",
    )
    .bind(Utc::now().to_rfc3339())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn upsert_group(
    transaction: &mut Transaction<'_, Sqlite>,
    name: &str,
) -> Result<Uuid, ApiError> {
    let normalized = wiremesh_domain::normalize_group_name(name)?;
    if let Some(id) = sqlx::query_scalar::<_, String>(
        "SELECT id FROM groups WHERE normalized_name=?",
    )
    .bind(&normalized)
    .fetch_optional(&mut **transaction)
    .await?
    {
        return parse_uuid(&id, "group");
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO groups(id,normalized_name,display_name,created_at) VALUES(?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(&normalized)
    .bind(name.trim())
    .bind(Utc::now().to_rfc3339())
    .execute(&mut **transaction)
    .await?;
    Ok(id)
}

async fn upsert_membership(
    transaction: &mut Transaction<'_, Sqlite>,
    group_id: Uuid,
    user_id: Uuid,
    source_kind: &str,
    source_id: &str,
    active: bool,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO group_memberships(id,group_id,user_id,source_kind,source_id,active,updated_at)
         VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(group_id,user_id,source_kind,source_id) DO UPDATE SET active=excluded.active,updated_at=excluded.updated_at",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(group_id.to_string())
    .bind(user_id.to_string())
    .bind(source_kind)
    .bind(source_id)
    .bind(active)
    .bind(Utc::now().to_rfc3339())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_ldap_entries(
    entries: Vec<LdapSnapshotEntry>,
) -> Result<Vec<LdapSnapshotEntry>, ApiError> {
    if entries.len() > 10_000 {
        return Err(ApiError::Validation("LDAP snapshot is too large".into()));
    }
    let mut external_ids = BTreeSet::new();
    let mut validated = Vec::with_capacity(entries.len());
    for mut entry in entries {
        entry.external_id = entry.external_id.trim().into();
        if entry.external_id.is_empty() || !external_ids.insert(entry.external_id.clone()) {
            return Err(ApiError::Validation(
                "LDAP immutable IDs must be non-empty and unique".into(),
            ));
        }
        entry.email = wiremesh_domain::normalize_email(&entry.email)?;
        if entry.name.trim().is_empty() {
            return Err(ApiError::Validation("LDAP user name is required".into()));
        }
        entry.groups = entry
            .groups
            .into_iter()
            .map(|group| wiremesh_domain::normalize_group_name(&group))
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect();
        validated.push(entry);
    }
    Ok(validated)
}

fn validate_provider_config(
    kind: ProviderKind,
    sync_interval: Option<u32>,
    config: &serde_json::Value,
) -> Result<(), ApiError> {
    let object = config
        .as_object()
        .ok_or_else(|| ApiError::Validation("provider config must be an object".into()))?;
    match kind {
        ProviderKind::Oidc => {
            let issuer = object.get("issuer_url").and_then(serde_json::Value::as_str);
            if !issuer.is_some_and(|value| value.starts_with("https://")) {
                return Err(ApiError::Validation(
                    "OIDC issuer_url must use HTTPS".into(),
                ));
            }
            for field in ["client_id", "client_secret", "redirect_url"] {
                if !object
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                {
                    return Err(ApiError::Validation(format!(
                        "OIDC {field} is required"
                    )));
                }
            }
            if !object
                .get("redirect_url")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.starts_with("https://"))
            {
                return Err(ApiError::Validation(
                    "OIDC redirect_url must use HTTPS".into(),
                ));
            }
            if !object
                .get("userinfo_url")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.starts_with("https://"))
            {
                return Err(ApiError::Validation(
                    "OIDC userinfo_url must use HTTPS and is required for profile and group claims"
                        .into(),
                ));
            }
        }
        ProviderKind::Ldap => {
            let url = object.get("url").and_then(serde_json::Value::as_str);
            let secure = url.is_some_and(|value| value.starts_with("ldaps://"))
                || (url.is_some_and(|value| value.starts_with("ldap://"))
                    && object
                        .get("start_tls")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true));
            if !secure {
                return Err(ApiError::Validation(
                    "LDAP must use LDAPS or LDAP with start_tls=true".into(),
                ));
            }
            if !sync_interval.is_some_and(|seconds| seconds >= 60) {
                return Err(ApiError::Validation(
                    "LDAP sync interval must be at least 60 seconds".into(),
                ));
            }
            for field in ["bind_dn", "bind_password", "base_dn"] {
                if !object
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                {
                    return Err(ApiError::Validation(format!(
                        "LDAP {field} is required"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn provider_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ProviderResponse, ApiError> {
    Ok(ProviderResponse {
        id: parse_uuid(&row.try_get::<String, _>("id")?, "identity provider")?,
        kind: match row.try_get::<String, _>("kind")?.as_str() {
            "oidc" => ProviderKind::Oidc,
            "ldap" => ProviderKind::Ldap,
            _ => return Err(ApiError::Internal(anyhow::anyhow!("invalid provider kind"))),
        },
        name: row.try_get("name")?,
        enabled: row.try_get("enabled")?,
        trusted_create: row.try_get("trusted_create")?,
        sync_interval_seconds: row
            .try_get::<Option<i64>, _>("sync_interval_seconds")?
            .map(|value| value as u32),
        last_successful_sync_at: row.try_get("last_successful_sync_at")?,
    })
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Sqlite>,
    action: &str,
    object_kind: &str,
    object_id: Option<Uuid>,
    details: serde_json::Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_events(id,occurred_at,actor_kind,action,object_kind,object_id,outcome,details_json)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(Utc::now().to_rfc3339())
    .bind("system")
    .bind(action)
    .bind(object_kind)
    .bind(object_id.map(|value| value.to_string()))
    .bind("success")
    .bind(details.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid {field} UUID: {error}")))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    async fn pool() -> SqlitePool {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    async fn ldap_provider(pool: &SqlitePool, vault: &SecretBox, name: &str) -> Uuid {
        create_provider(
            pool,
            vault,
            CreateProviderRequest {
                kind: ProviderKind::Ldap,
                name: name.into(),
                trusted_create: true,
                sync_interval_seconds: Some(300),
                config: serde_json::json!({
                    "url":"ldaps://directory.example",
                    "bind_dn":"cn=wiremesh,dc=example",
                    "bind_password":"test-only",
                    "base_dn":"dc=example"
                }),
            },
        )
        .await
        .unwrap()
        .id
    }

    fn entry() -> LdapSnapshotEntry {
        LdapSnapshotEntry {
            external_id: "immutable-1".into(),
            email: "person@example.com".into(),
            name: "Original Name".into(),
            title: "Engineer".into(),
            groups: vec!["Engineering".into()],
            active: true,
        }
    }

    #[tokio::test]
    async fn multiple_ldap_sources_disable_only_when_all_are_inactive() {
        let pool = pool().await;
        let vault = SecretBox::from_bytes(&[3_u8; 32]).unwrap();
        let first = ldap_provider(&pool, &vault, "first").await;
        let second = ldap_provider(&pool, &vault, "second").await;
        apply_ldap_snapshot(&pool, first, LdapSyncSnapshot { complete: true, entries: vec![entry()] }).await.unwrap();
        let mut second_entry = entry();
        second_entry.external_id = "other-source-id".into();
        second_entry.name = "Changed Name".into();
        apply_ldap_snapshot(&pool, second, LdapSyncSnapshot { complete: true, entries: vec![second_entry] }).await.unwrap();
        apply_ldap_snapshot(&pool, first, LdapSyncSnapshot { complete: true, entries: vec![] }).await.unwrap();
        let user = service::list_users(&pool).await.unwrap().pop().unwrap();
        assert!(!user.ldap_disabled);
        assert_eq!(user.name, "Original Name");
        apply_ldap_snapshot(&pool, second, LdapSyncSnapshot { complete: true, entries: vec![] }).await.unwrap();
        assert!(service::get_user(&pool, user.id).await.unwrap().ldap_disabled);
        apply_ldap_snapshot(&pool, first, LdapSyncSnapshot { complete: true, entries: vec![entry()] }).await.unwrap();
        assert!(!service::get_user(&pool, user.id).await.unwrap().ldap_disabled);
    }

    #[tokio::test]
    async fn partial_sync_preserves_previous_identity_state() {
        let pool = pool().await;
        let vault = SecretBox::from_bytes(&[4_u8; 32]).unwrap();
        let provider = ldap_provider(&pool, &vault, "directory").await;
        apply_ldap_snapshot(&pool, provider, LdapSyncSnapshot { complete: true, entries: vec![entry()] }).await.unwrap();
        assert!(apply_ldap_snapshot(&pool, provider, LdapSyncSnapshot { complete: false, entries: vec![] }).await.is_err());
        assert!(!service::list_users(&pool).await.unwrap()[0].ldap_disabled);
    }

    #[tokio::test]
    async fn ldap_precedence_and_provider_enablement_control_effective_groups() {
        let pool = pool().await;
        let vault = SecretBox::from_bytes(&[5_u8; 32]).unwrap();
        crate::auth::bootstrap_admin(&pool, "root@example.com", "Root")
            .await
            .unwrap();
        let oidc = create_provider(
            &pool,
            &vault,
            CreateProviderRequest {
                kind: ProviderKind::Oidc,
                name: "work-sso".into(),
                trusted_create: true,
                sync_interval_seconds: None,
                config: serde_json::json!({
                    "issuer_url":"https://identity.example",
                    "client_id":"wiremesh",
                    "client_secret":"test-only",
                    "redirect_url":"https://wiremesh.example/oidc/callback",
                    "userinfo_url":"https://identity.example/userinfo"
                }),
            },
        )
        .await
        .unwrap()
        .id;
        let person = apply_verified_oidc_claims(
            &pool,
            oidc,
            OidcClaims {
                subject: "oidc-person".into(),
                email: "person@example.com".into(),
                email_verified: true,
                name: "Person".into(),
                title: String::new(),
                groups: vec![crate::auth::ADMIN_GROUP.into()],
            },
        )
        .await
        .unwrap();
        let ldap = ldap_provider(&pool, &vault, "directory").await;
        apply_ldap_snapshot(
            &pool,
            ldap,
            LdapSyncSnapshot {
                complete: true,
                entries: vec![entry()],
            },
        )
        .await
        .unwrap();

        let effective_admin: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM effective_group_memberships gm
             JOIN groups g ON g.id=gm.group_id
             WHERE gm.user_id=? AND g.normalized_name='wiremesh-admins'",
        )
        .bind(person.id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(effective_admin, 0, "LDAP linkage must suppress OIDC groups");

        let engineering: String = sqlx::query_scalar(
            "SELECT id FROM groups WHERE normalized_name='engineering'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let members = service::list_group_members(&pool, engineering.parse().unwrap())
            .await
            .unwrap();
        assert_eq!(members[0].sources, vec!["ldap:directory"]);

        set_provider_enabled(&pool, ldap, false).await.unwrap();
        let effective_external: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM effective_group_memberships WHERE user_id=?",
        )
        .bind(person.id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(effective_external, 0);
        assert!(service::get_user(&pool, person.id).await.unwrap().ldap_disabled);
    }
}
