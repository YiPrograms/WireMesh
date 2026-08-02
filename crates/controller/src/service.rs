use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddrV4},
};

use chrono::Utc;
use ipnet::Ipv4Net;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;
use wiremesh_domain::{
    ClientConfigModel, ClientOptions, ClientPeer, ClientPool, ConfigChangeKind, GatewayRoute,
    validate_endpoint_routes, validate_gateway_routes, validate_wireguard_public_key,
};

use crate::{
    desired,
    error::ApiError,
    models::{
        AcknowledgeConfigRequest, AclResponse, AclRuleModel, AgentResponse, AuditEventResponse,
        CreateAgentRequest, CreateDeviceRequest, CreateGroupRequest, CreateSiteRequest,
        CreateUserRequest, CreatedAgentResponse, DashboardResponse, DeviceConfigResponse,
        DeviceResponse, GroupMemberResponse, GroupResponse, PeerProvisioningResponse,
        ReplaceAclRequest, RotateDeviceKeyRequest, RotatedAgentSecretResponse, SiteResponse,
        SystemSettingsResponse, UpdateSiteRequest, UpdateSystemSettingsRequest, UserResponse,
    },
};

fn now() -> String {
    Utc::now().to_rfc3339()
}

pub async fn create_agent(
    pool: &SqlitePool,
    request: CreateAgentRequest,
) -> Result<CreatedAgentResponse, ApiError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(ApiError::Validation("agent name must contain 1-128 characters".into()));
    }
    let id = Uuid::now_v7();
    let secret = crate::auth::random_secret();
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO agents(id,name,kind,current_secret_hash,created_at,updated_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(request.kind.as_str())
    .bind(crate::auth::token_digest(secret.as_bytes()))
    .bind(&timestamp)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = result {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            return Err(ApiError::Conflict("agent name already exists".into()));
        }
        return Err(error.into());
    }
    audit(
        &mut transaction,
        None,
        "system",
        "agent.create",
        "agent",
        Some(id),
        "success",
        serde_json::json!({"name": name, "kind": request.kind.as_str()}),
    )
    .await?;
    transaction.commit().await?;
    Ok(CreatedAgentResponse {
        id,
        name: name.into(),
        kind: request.kind.as_str().into(),
        secret,
    })
}

pub async fn list_agents(pool: &SqlitePool) -> Result<Vec<AgentResponse>, ApiError> {
    let rows = sqlx::query("SELECT id,name,kind,version,last_seen_at FROM agents ORDER BY name")
        .fetch_all(pool)
        .await?;
    let stale_before = Utc::now() - chrono::Duration::seconds(45);
    rows.into_iter()
        .map(|row| {
            let last_seen_at: Option<String> = row.try_get("last_seen_at")?;
            let online = last_seen_at
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|value| value > stale_before);
            Ok(AgentResponse {
                id: parse_uuid(&row.try_get::<String, _>("id")?, "agent")?,
                name: row.try_get("name")?,
                kind: row.try_get("kind")?,
                version: row.try_get("version")?,
                last_seen_at,
                online,
            })
        })
        .collect()
}

pub async fn rotate_agent_secret(
    pool: &SqlitePool,
    agent_id: Uuid,
) -> Result<RotatedAgentSecretResponse, ApiError> {
    let secret = crate::auth::random_secret();
    let mut transaction = pool.begin().await?;
    let result = sqlx::query("UPDATE agents SET next_secret_hash=?,updated_at=? WHERE id=?")
        .bind(crate::auth::token_digest(secret.as_bytes()))
        .bind(now())
        .bind(agent_id.to_string())
        .execute(&mut *transaction)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("agent does not exist".into()));
    }
    audit(
        &mut transaction,
        None,
        "system",
        "agent.secret.rotate",
        "agent",
        Some(agent_id),
        "success",
        serde_json::json!({"overlap": true}),
    )
    .await?;
    transaction.commit().await?;
    Ok(RotatedAgentSecretResponse { agent_id, secret })
}

pub async fn promote_agent_secret(pool: &SqlitePool, agent_id: Uuid) -> Result<(), ApiError> {
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "UPDATE agents SET current_secret_hash=next_secret_hash,next_secret_hash=NULL,updated_at=?
         WHERE id=? AND next_secret_hash IS NOT NULL",
    )
    .bind(now())
    .bind(agent_id.to_string())
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict("agent has no next secret to promote".into()));
    }
    audit(
        &mut transaction,
        None,
        "system",
        "agent.secret.promote",
        "agent",
        Some(agent_id),
        "success",
        serde_json::json!({"overlap": false}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|error| {
        ApiError::Internal(anyhow::anyhow!("invalid {field} UUID in database: {error}"))
    })
}

fn parse_ip(value: &str, field: &str) -> Result<Ipv4Addr, ApiError> {
    value.parse().map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "invalid {field} address in database: {error}"
        ))
    })
}

fn parse_net(value: &str, field: &str) -> Result<Ipv4Net, ApiError> {
    value.parse().map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "invalid {field} network in database: {error}"
        ))
    })
}

async fn validate_gateway_endpoint_routes(
    pool: &SqlitePool,
    routes: &[GatewayRoute],
    replaced_gateway: Option<Uuid>,
    candidate: Option<(&str, u16)>,
) -> Result<(), ApiError> {
    let rows = sqlx::query(
        "SELECT id,endpoint_host,COALESCE(public_port,listen_port,51820) AS endpoint_port
         FROM gateways",
    )
    .fetch_all(pool)
    .await?;
    let mut endpoints = Vec::new();
    for row in rows {
        let gateway_id = parse_uuid(&row.try_get::<String, _>("id")?, "gateway")?;
        if replaced_gateway == Some(gateway_id) {
            continue;
        }
        let host: String = row.try_get("endpoint_host")?;
        if let Ok(address) = host.parse::<Ipv4Addr>() {
            let port = u16::try_from(row.try_get::<i64, _>("endpoint_port")?)
                .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid gateway port")))?;
            endpoints.push(SocketAddrV4::new(address, port));
        }
    }
    if let Some((host, port)) = candidate
        && let Ok(address) = host.parse::<Ipv4Addr>()
    {
        endpoints.push(SocketAddrV4::new(address, port));
    }
    validate_endpoint_routes(routes, &endpoints)?;
    Ok(())
}

pub async fn system_settings(pool: &SqlitePool) -> Result<SystemSettingsResponse, ApiError> {
    let rows = sqlx::query("SELECT key, value_json FROM system_settings")
        .fetch_all(pool)
        .await?;
    let mut client_pool = None;
    let mut default_device_limit = None;
    let mut client_options = None;
    for row in rows {
        let key: String = row.try_get("key")?;
        let value: String = row.try_get("value_json")?;
        match key.as_str() {
            "client_pool" => {
                let raw: String = serde_json::from_str(&value)
                    .map_err(|error| ApiError::Internal(error.into()))?;
                client_pool = Some(parse_net(&raw, "client pool")?);
            }
            "default_device_limit" => {
                default_device_limit = Some(
                    serde_json::from_str::<u32>(&value)
                        .map_err(|error| ApiError::Internal(error.into()))?,
                );
            }
            "client_options" => {
                client_options = Some(
                    serde_json::from_str::<ClientOptions>(&value)
                        .map_err(|error| ApiError::Internal(error.into()))?,
                );
            }
            _ => {}
        }
    }
    Ok(SystemSettingsResponse {
        client_pool: client_pool
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("client_pool setting missing")))?,
        default_device_limit: default_device_limit.ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("default_device_limit setting missing"))
        })?,
        client_options: client_options
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("client_options setting missing")))?,
    })
}

pub async fn dashboard(pool: &SqlitePool) -> Result<DashboardResponse, ApiError> {
    let settings = system_settings(pool).await?;
    let client_pool = ClientPool::new(settings.client_pool)?;
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE soft_deleted_at IS NULL")
        .fetch_one(pool)
        .await?;
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE status != 'deleted'")
        .fetch_one(pool)
        .await?;
    let sites: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sites")
        .fetch_one(pool)
        .await?;
    let gateways_online: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateways WHERE julianday(last_seen_at) >= julianday('now', '-45 seconds')",
    )
    .fetch_one(pool)
    .await?;
    let gateways_stale: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateways WHERE last_seen_at IS NULL OR julianday(last_seen_at) < julianday('now', '-45 seconds')",
    )
    .fetch_one(pool)
    .await?;
    let pool_allocated: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ip_leases WHERE quarantined_at IS NULL AND released_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    let pool_quarantined: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ip_leases WHERE quarantined_at IS NOT NULL AND released_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    let pool_capacity = client_pool.usable_capacity();
    let pool_usage_percent = if pool_capacity == 0 {
        100.0
    } else {
        ((pool_allocated + pool_quarantined) as f64 / pool_capacity as f64) * 100.0
    };
    Ok(DashboardResponse {
        users,
        devices,
        sites,
        gateways_online,
        gateways_stale,
        client_pool: settings.client_pool,
        pool_capacity,
        pool_allocated,
        pool_quarantined,
        pool_usage_percent,
    })
}

pub async fn prometheus_metrics(pool: &SqlitePool) -> Result<String, ApiError> {
    let dashboard = dashboard(pool).await?;
    let gateways_drifted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateways WHERE desired_revision != applied_revision",
    )
    .fetch_one(pool)
    .await?;
    let outdated_profiles: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM devices WHERE status != 'deleted' AND config_revision > acknowledged_revision",
    )
    .fetch_one(pool)
    .await?;
    let mail_jobs_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_jobs WHERE status IN ('pending','sending')",
    )
    .fetch_one(pool)
    .await?;
    let armed_migrations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subnet_migrations WHERE status='armed'",
    )
    .fetch_one(pool)
    .await?;
    Ok(format!(
        concat!(
            "# HELP wiremesh_users Users not soft-deleted.\n",
            "# TYPE wiremesh_users gauge\n",
            "wiremesh_users {}\n",
            "# HELP wiremesh_devices Active or revoked device records.\n",
            "# TYPE wiremesh_devices gauge\n",
            "wiremesh_devices {}\n",
            "# HELP wiremesh_gateways Gateway connectivity by state.\n",
            "# TYPE wiremesh_gateways gauge\n",
            "wiremesh_gateways{{state=\"online\"}} {}\n",
            "wiremesh_gateways{{state=\"stale\"}} {}\n",
            "# HELP wiremesh_gateway_drift Gateways whose applied revision differs from desired.\n",
            "# TYPE wiremesh_gateway_drift gauge\n",
            "wiremesh_gateway_drift {}\n",
            "# HELP wiremesh_client_pool_addresses Client address-pool usage.\n",
            "# TYPE wiremesh_client_pool_addresses gauge\n",
            "wiremesh_client_pool_addresses{{state=\"capacity\"}} {}\n",
            "wiremesh_client_pool_addresses{{state=\"allocated\"}} {}\n",
            "wiremesh_client_pool_addresses{{state=\"quarantined\"}} {}\n",
            "# HELP wiremesh_outdated_profiles Device profiles awaiting acknowledgement.\n",
            "# TYPE wiremesh_outdated_profiles gauge\n",
            "wiremesh_outdated_profiles {}\n",
            "# HELP wiremesh_mail_jobs_pending Durable email jobs waiting to be sent.\n",
            "# TYPE wiremesh_mail_jobs_pending gauge\n",
            "wiremesh_mail_jobs_pending {}\n",
            "# HELP wiremesh_armed_migrations Scheduled subnet migrations currently armed.\n",
            "# TYPE wiremesh_armed_migrations gauge\n",
            "wiremesh_armed_migrations {}\n",
            "# HELP wiremesh_build_info WireMesh controller build information.\n",
            "# TYPE wiremesh_build_info gauge\n",
            "wiremesh_build_info{{version=\"{}\"}} 1\n"
        ),
        dashboard.users,
        dashboard.devices,
        dashboard.gateways_online,
        dashboard.gateways_stale,
        gateways_drifted,
        dashboard.pool_capacity,
        dashboard.pool_allocated,
        dashboard.pool_quarantined,
        outdated_profiles,
        mail_jobs_pending,
        armed_migrations,
        crate::VERSION,
    ))
}

pub async fn create_user(
    pool: &SqlitePool,
    request: CreateUserRequest,
) -> Result<UserResponse, ApiError> {
    let email = wiremesh_domain::normalize_email(&request.email)?;
    let name = request.name.trim();
    if name.is_empty() {
        return Err(ApiError::Validation("name is required".into()));
    }
    let id = Uuid::now_v7();
    let identity_id = Uuid::now_v7();
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO users(id,email,name,title,creator_kind,created_at,updated_at) VALUES(?,?,?,?,? ,?,?)",
    )
    .bind(id.to_string())
    .bind(&email)
    .bind(name)
    .bind(request.title.trim())
    .bind("local")
    .bind(&timestamp)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = result {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            return Err(ApiError::Conflict("email already exists".into()));
        }
        return Err(error.into());
    }
    sqlx::query(
        "INSERT INTO user_identities(id,user_id,kind,external_id,current_email,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(identity_id.to_string())
    .bind(id.to_string())
    .bind("local")
    .bind(email.clone())
    .bind(email.clone())
    .bind(&timestamp)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    audit(
        &mut transaction,
        None,
        "system",
        "user.create",
        "user",
        Some(id),
        "success",
        serde_json::json!({"email": email}),
    )
    .await?;
    transaction.commit().await?;
    get_user(pool, id).await
}

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<UserResponse>, ApiError> {
    let default_limit = system_settings(pool).await?.default_device_limit;
    let rows = sqlx::query(
        "SELECT id,email,name,title,manual_disabled,ldap_disabled,device_limit_override,soft_deleted_at,purged_at,created_at FROM users ORDER BY email",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| user_from_row(row, default_limit))
        .collect()
}

pub async fn get_user(pool: &SqlitePool, id: Uuid) -> Result<UserResponse, ApiError> {
    let default_limit = system_settings(pool).await?.default_device_limit;
    let row = sqlx::query(
        "SELECT id,email,name,title,manual_disabled,ldap_disabled,device_limit_override,soft_deleted_at,purged_at,created_at FROM users WHERE id=?",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("user does not exist".into()))?;
    user_from_row(row, default_limit)
}

fn user_from_row(
    row: sqlx::sqlite::SqliteRow,
    default_limit: u32,
) -> Result<UserResponse, ApiError> {
    let manual_disabled: bool = row.try_get("manual_disabled")?;
    let ldap_disabled: bool = row.try_get("ldap_disabled")?;
    let soft_deleted_at: Option<String> = row.try_get("soft_deleted_at")?;
    let override_limit: Option<i64> = row.try_get("device_limit_override")?;
    Ok(UserResponse {
        id: parse_uuid(row.try_get::<String, _>("id")?.as_str(), "user")?,
        email: row.try_get("email")?,
        name: row.try_get("name")?,
        title: row.try_get("title")?,
        manual_disabled,
        ldap_disabled,
        disabled: manual_disabled || ldap_disabled || soft_deleted_at.is_some(),
        soft_deleted: soft_deleted_at.is_some(),
        purged: row.try_get::<Option<String>, _>("purged_at")?.is_some(),
        device_limit: override_limit
            .map(|value| value as u32)
            .unwrap_or(default_limit),
        created_at: row.try_get("created_at")?,
    })
}

pub async fn soft_delete_user(pool: &SqlitePool, id: Uuid) -> Result<UserResponse, ApiError> {
    ensure_no_active_migration(pool).await?;
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    let row = sqlx::query("SELECT soft_deleted_at,purged_at FROM users WHERE id=?")
        .bind(id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::NotFound("user does not exist".into()))?;
    if row.try_get::<Option<String>, _>("purged_at")?.is_some() {
        return Err(ApiError::Conflict("purged users cannot be changed".into()));
    }
    if row.try_get::<Option<String>, _>("soft_deleted_at")?.is_some() {
        transaction.rollback().await?;
        return get_user(pool, id).await;
    }
    ensure_not_last_admin(&mut transaction, id).await?;
    let addresses = active_addresses_for_user(&mut transaction, id).await?;
    let device_ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM devices WHERE user_id=? AND status='active' ORDER BY id",
    )
    .bind(id.to_string())
    .fetch_all(&mut *transaction)
    .await?;
    let mut gateway_ids = BTreeSet::new();
    for device_id in device_ids {
        gateway_ids.extend(
            desired::gateway_ids_that_may_hold_device(
                &mut transaction,
                parse_uuid(&device_id, "device")?,
            )
            .await?,
        );
    }
    sqlx::query("UPDATE users SET soft_deleted_at=?,updated_at=? WHERE id=?")
        .bind(&timestamp)
        .bind(&timestamp)
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    let states = desired::rebuild_gateways(&mut transaction, gateway_ids, addresses).await?;
    for state in &states {
        sqlx::query(
            "INSERT INTO user_deletion_gateway_acks(user_id,gateway_id,required_revision)
             VALUES(?,?,?) ON CONFLICT(user_id,gateway_id)
             DO UPDATE SET required_revision=excluded.required_revision,acknowledged_at=NULL",
        )
        .bind(id.to_string())
        .bind(state.gateway_id.to_string())
        .bind(state.revision as i64)
        .execute(&mut *transaction)
        .await?;
    }
    audit(
        &mut transaction,
        None,
        "system",
        "user.soft_delete",
        "user",
        Some(id),
        "success",
        serde_json::json!({"pending_gateways": states.len()}),
    )
    .await?;
    transaction.commit().await?;
    get_user(pool, id).await
}

pub async fn restore_user(pool: &SqlitePool, id: Uuid) -> Result<UserResponse, ApiError> {
    ensure_no_active_migration(pool).await?;
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    let row = sqlx::query("SELECT soft_deleted_at,purged_at FROM users WHERE id=?")
        .bind(id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::NotFound("user does not exist".into()))?;
    if row.try_get::<Option<String>, _>("purged_at")?.is_some() {
        return Err(ApiError::Conflict("a purged user cannot be restored".into()));
    }
    if row.try_get::<Option<String>, _>("soft_deleted_at")?.is_none() {
        return Err(ApiError::Conflict("user is not soft-deleted".into()));
    }
    sqlx::query("UPDATE users SET soft_deleted_at=NULL,updated_at=? WHERE id=?")
        .bind(&timestamp)
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM user_deletion_gateway_acks WHERE user_id=?")
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    desired::rebuild_gateways_for_user(&mut transaction, id, Vec::new()).await?;
    audit(
        &mut transaction,
        None,
        "system",
        "user.restore",
        "user",
        Some(id),
        "success",
        serde_json::json!({}),
    )
    .await?;
    transaction.commit().await?;
    get_user(pool, id).await
}

pub async fn purge_user(pool: &SqlitePool, id: Uuid) -> Result<UserResponse, ApiError> {
    ensure_no_active_migration(pool).await?;
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    let row = sqlx::query("SELECT email,soft_deleted_at,purged_at FROM users WHERE id=?")
        .bind(id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::NotFound("user does not exist".into()))?;
    if row.try_get::<Option<String>, _>("purged_at")?.is_some() {
        transaction.rollback().await?;
        return get_user(pool, id).await;
    }
    if row.try_get::<Option<String>, _>("soft_deleted_at")?.is_none() {
        return Err(ApiError::Conflict("soft-delete the user before purge".into()));
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_deletion_gateway_acks WHERE user_id=? AND acknowledged_at IS NULL",
    )
    .bind(id.to_string())
    .fetch_one(&mut *transaction)
    .await?;
    if pending > 0 {
        return Err(ApiError::Conflict(format!(
            "{pending} gateway(s) have not acknowledged peer removal"
        )));
    }
    let device_ids = sqlx::query_scalar::<_, String>("SELECT id FROM devices WHERE user_id=?")
        .bind(id.to_string())
        .fetch_all(&mut *transaction)
        .await?;
    for device_id in &device_ids {
        let lease_ids = sqlx::query_scalar::<_, String>("SELECT id FROM ip_leases WHERE device_id=?")
            .bind(device_id)
            .fetch_all(&mut *transaction)
            .await?;
        for lease_id in lease_ids {
            sqlx::query("DELETE FROM lease_gateway_acks WHERE lease_id=?")
                .bind(&lease_id)
                .execute(&mut *transaction)
                .await?;
        }
        sqlx::query("DELETE FROM ip_leases WHERE device_id=?")
            .bind(device_id)
            .execute(&mut *transaction)
            .await?;
        let key_ids = sqlx::query_scalar::<_, String>(
            "SELECT id FROM key_registry WHERE owner_kind='device' AND owner_id=?",
        )
        .bind(device_id)
        .fetch_all(&mut *transaction)
        .await?;
        for key_id in key_ids {
            sqlx::query("DELETE FROM key_gateway_acks WHERE key_id=?")
                .bind(&key_id)
                .execute(&mut *transaction)
                .await?;
        }
        sqlx::query("DELETE FROM key_registry WHERE owner_kind='device' AND owner_id=?")
            .bind(device_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM config_snapshots WHERE device_id=?")
            .bind(device_id)
            .execute(&mut *transaction)
            .await?;
    }
    sqlx::query("DELETE FROM devices WHERE user_id=?")
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    for statement in [
        "DELETE FROM acl_rule_users WHERE user_id=?",
        "DELETE FROM group_memberships WHERE user_id=?",
        "DELETE FROM local_passwords WHERE user_id=?",
        "DELETE FROM passkeys WHERE user_id=?",
        "DELETE FROM one_time_tokens WHERE user_id=?",
        "DELETE FROM sessions WHERE user_id=?",
        "DELETE FROM user_identities WHERE user_id=?",
        "DELETE FROM user_deletion_gateway_acks WHERE user_id=?",
    ] {
        sqlx::query(statement)
            .bind(id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    let old_email: String = row.try_get("email")?;
    sqlx::query(
        "UPDATE users SET email=?,name='Purged user',title='',manual_disabled=1,ldap_disabled=0,
         device_limit_override=NULL,purged_at=?,updated_at=? WHERE id=?",
    )
    .bind(format!("purged+{id}@invalid"))
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(id.to_string())
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM mail_jobs WHERE recipient=? AND status IN ('pending','sending','failed')")
        .bind(old_email)
        .execute(&mut *transaction)
        .await?;
    audit(
        &mut transaction,
        None,
        "system",
        "user.purge",
        "user",
        Some(id),
        "success",
        serde_json::json!({"devices_removed": device_ids.len()}),
    )
    .await?;
    transaction.commit().await?;
    get_user(pool, id).await
}

async fn ensure_no_active_migration(pool: &SqlitePool) -> Result<(), ApiError> {
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subnet_migrations WHERE status IN ('preparing','armed')",
    )
    .fetch_one(pool)
    .await?;
    if active > 0 {
        Err(ApiError::Conflict(
            "user lifecycle changes are paused during an active subnet migration".into(),
        ))
    } else {
        Ok(())
    }
}

async fn ensure_not_last_admin(
    transaction: &mut Transaction<'_, Sqlite>,
    user_id: Uuid,
) -> Result<(), ApiError> {
    let is_admin: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM effective_group_memberships gm JOIN groups g ON g.id=gm.group_id
         WHERE gm.user_id=? AND g.normalized_name='wiremesh-admins'",
    )
    .bind(user_id.to_string())
    .fetch_one(&mut **transaction)
    .await?;
    if is_admin > 0 {
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT u.id) FROM users u
             JOIN effective_group_memberships gm ON gm.user_id=u.id
             JOIN groups g ON g.id=gm.group_id AND g.normalized_name='wiremesh-admins'
             WHERE u.manual_disabled=0 AND u.ldap_disabled=0 AND u.soft_deleted_at IS NULL AND u.id != ?",
        )
        .bind(user_id.to_string())
        .fetch_one(&mut **transaction)
        .await?;
        if remaining == 0 {
            return Err(ApiError::Conflict(
                "cannot remove the last enabled administrator".into(),
            ));
        }
    }
    Ok(())
}

/// Enforces the administrator lockout invariant after a change that can alter
/// effective external memberships or user enablement. A pristine database is
/// allowed to have no administrator until `bootstrap-admin` creates the
/// canonical group for the first time.
pub(crate) async fn ensure_enabled_admin_exists(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<(), ApiError> {
    let admin_group_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM groups WHERE normalized_name='wiremesh-admins'",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if admin_group_exists == 0 {
        return Ok(());
    }
    let enabled_admins: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT u.id) FROM users u
         JOIN effective_group_memberships gm ON gm.user_id=u.id
         JOIN groups g ON g.id=gm.group_id AND g.normalized_name='wiremesh-admins'
         WHERE u.manual_disabled=0 AND u.ldap_disabled=0 AND u.soft_deleted_at IS NULL",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if enabled_admins == 0 {
        Err(ApiError::Conflict(
            "change would leave WireMesh without an enabled administrator".into(),
        ))
    } else {
        Ok(())
    }
}

pub async fn set_user_disabled(
    pool: &SqlitePool,
    id: Uuid,
    disabled: bool,
) -> Result<UserResponse, ApiError> {
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM users WHERE id=?")
        .bind(id.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("user does not exist".into()));
    }
    if disabled {
        let is_admin: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM effective_group_memberships gm JOIN groups g ON g.id=gm.group_id
             WHERE gm.user_id=? AND g.normalized_name='wiremesh-admins'",
        )
        .bind(id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        if is_admin > 0 {
            let enabled_admins: i64 = sqlx::query_scalar(
                "SELECT COUNT(DISTINCT u.id) FROM users u
                 JOIN effective_group_memberships gm ON gm.user_id=u.id
                 JOIN groups g ON g.id=gm.group_id AND g.normalized_name='wiremesh-admins'
                 WHERE u.manual_disabled=0 AND u.ldap_disabled=0 AND u.soft_deleted_at IS NULL AND u.id != ?",
            )
            .bind(id.to_string())
            .fetch_one(&mut *transaction)
            .await?;
            if enabled_admins == 0 {
                return Err(ApiError::Conflict(
                    "cannot disable the last enabled administrator".into(),
                ));
            }
        }
    }
    sqlx::query("UPDATE users SET manual_disabled=?,updated_at=? WHERE id=?")
        .bind(disabled)
        .bind(&timestamp)
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    ensure_enabled_admin_exists(&mut transaction).await?;
    if disabled {
        sqlx::query("DELETE FROM sessions WHERE user_id=?")
            .bind(id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    let addresses = sqlx::query_scalar::<_, String>(
        "SELECT vpn_address FROM devices WHERE user_id=? AND status='active'",
    )
    .bind(id.to_string())
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|value| parse_ip(&value, "device"))
    .collect::<Result<Vec<_>, _>>()?;
    desired::rebuild_all_gateways(
        &mut transaction,
        if disabled { addresses } else { Vec::new() },
    )
    .await?;
    audit(
        &mut transaction,
        None,
        "system",
        "user.disable",
        "user",
        Some(id),
        "success",
        serde_json::json!({"disabled": disabled}),
    )
    .await?;
    transaction.commit().await?;
    get_user(pool, id).await
}

pub async fn create_group(
    pool: &SqlitePool,
    request: CreateGroupRequest,
) -> Result<GroupResponse, ApiError> {
    let normalized = wiremesh_domain::normalize_group_name(&request.name)?;
    let display = request.name.trim();
    let id = Uuid::now_v7();
    let result = sqlx::query(
        "INSERT INTO groups(id,normalized_name,display_name,created_at) VALUES(?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(&normalized)
    .bind(display)
    .bind(now())
    .execute(pool)
    .await;
    if let Err(error) = result {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            return Err(ApiError::Conflict("group name already exists".into()));
        }
        return Err(error.into());
    }
    append_audit(
        pool,
        "group.create",
        "group",
        Some(id),
        serde_json::json!({"name": normalized}),
    )
    .await?;
    Ok(GroupResponse {
        id,
        normalized_name: normalized,
        display_name: display.into(),
        members: 0,
    })
}

pub async fn list_groups(pool: &SqlitePool) -> Result<Vec<GroupResponse>, ApiError> {
    let rows = sqlx::query(
        "SELECT g.id,g.normalized_name,g.display_name,COUNT(DISTINCT gm.user_id) AS members FROM groups g LEFT JOIN effective_group_memberships gm ON gm.group_id=g.id GROUP BY g.id ORDER BY g.normalized_name",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(GroupResponse {
                id: parse_uuid(row.try_get::<String, _>("id")?.as_str(), "group")?,
                normalized_name: row.try_get("normalized_name")?,
                display_name: row.try_get("display_name")?,
                members: row.try_get("members")?,
            })
        })
        .collect()
}

pub async fn list_group_members(
    pool: &SqlitePool,
    group_id: Uuid,
) -> Result<Vec<GroupMemberResponse>, ApiError> {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE id=?")
        .bind(group_id.to_string())
        .fetch_one(pool)
        .await?;
    if exists == 0 {
        return Err(ApiError::NotFound("group does not exist".into()));
    }
    let rows = sqlx::query(
        "SELECT u.id,u.email,u.name,
                json_group_array(DISTINCT CASE
                    WHEN gm.source_kind='local' THEN 'local'
                    ELSE gm.source_kind || ':' || COALESCE(p.name,gm.source_id)
                END) AS sources
         FROM effective_group_memberships gm
         JOIN users u ON u.id=gm.user_id
         LEFT JOIN identity_providers p ON p.id=gm.source_id
         WHERE gm.group_id=?
         GROUP BY u.id ORDER BY u.email",
    )
    .bind(group_id.to_string())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(GroupMemberResponse {
                user_id: parse_uuid(&row.try_get::<String, _>("id")?, "user")?,
                email: row.try_get("email")?,
                name: row.try_get("name")?,
                sources: serde_json::from_str(&row.try_get::<String, _>("sources")?)
                    .map_err(|error| ApiError::Internal(error.into()))?,
            })
        })
        .collect()
}

pub async fn add_local_group_member(
    pool: &SqlitePool,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<(), ApiError> {
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    ensure_group_and_user(&mut transaction, group_id, user_id).await?;
    sqlx::query(
        "INSERT INTO group_memberships(id,group_id,user_id,source_kind,source_id,active,updated_at)
         VALUES(?,?,?,?,?,1,?)
         ON CONFLICT(group_id,user_id,source_kind,source_id) DO UPDATE SET active=1,updated_at=excluded.updated_at",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(group_id.to_string())
    .bind(user_id.to_string())
    .bind("local")
    .bind("manual")
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    refresh_user_configs(&mut transaction, user_id).await?;
    desired::rebuild_all_gateways(&mut transaction, Vec::new()).await?;
    audit(
        &mut transaction,
        None,
        "system",
        "group.member.add",
        "group",
        Some(group_id),
        "success",
        serde_json::json!({"user_id": user_id, "source": "local"}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn remove_local_group_member(
    pool: &SqlitePool,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<(), ApiError> {
    let mut transaction = pool.begin().await?;
    ensure_group_and_user(&mut transaction, group_id, user_id).await?;
    let normalized: String = sqlx::query_scalar("SELECT normalized_name FROM groups WHERE id=?")
        .bind(group_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE group_memberships SET active=0,updated_at=?
         WHERE group_id=? AND user_id=? AND source_kind='local'",
    )
    .bind(now())
    .bind(group_id.to_string())
    .bind(user_id.to_string())
    .execute(&mut *transaction)
    .await?;
    if normalized == crate::auth::ADMIN_GROUP {
        ensure_enabled_admin_exists(&mut transaction).await?;
    }
    let addresses = active_addresses_for_user(&mut transaction, user_id).await?;
    refresh_user_configs(&mut transaction, user_id).await?;
    desired::rebuild_all_gateways(&mut transaction, addresses).await?;
    audit(
        &mut transaction,
        None,
        "system",
        "group.member.remove",
        "group",
        Some(group_id),
        "success",
        serde_json::json!({"user_id": user_id, "source": "local"}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn ensure_group_and_user(
    transaction: &mut Transaction<'_, Sqlite>,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<(), ApiError> {
    let group: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE id=?")
        .bind(group_id.to_string())
        .fetch_one(&mut **transaction)
        .await?;
    let user: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id=?")
        .bind(user_id.to_string())
        .fetch_one(&mut **transaction)
        .await?;
    if group == 0 {
        Err(ApiError::NotFound("group does not exist".into()))
    } else if user == 0 {
        Err(ApiError::NotFound("user does not exist".into()))
    } else {
        Ok(())
    }
}

pub async fn create_site(
    pool: &SqlitePool,
    request: CreateSiteRequest,
) -> Result<SiteResponse, ApiError> {
    if request.name.trim().is_empty() || request.routes.is_empty() {
        return Err(ApiError::Validation(
            "site name and at least one route are required".into(),
        ));
    }
    if request.interface_name.is_empty()
        || request.interface_name.len() > 15
        || !request.interface_name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(ApiError::Validation("interface name is invalid".into()));
    }
    if request.endpoint_host.trim().is_empty()
        || request.endpoint_host.chars().any(char::is_whitespace)
    {
        return Err(ApiError::Validation("endpoint host is invalid".into()));
    }
    if request.public_port == Some(0) || request.listen_port == Some(0) {
        return Err(ApiError::Validation("gateway ports cannot be zero".into()));
    }
    if let Some(public_key) = &request.public_key {
        validate_wireguard_public_key(public_key)?;
    }
    let settings = system_settings(pool).await?;
    let existing = sqlx::query(
        "SELECT sr.cidr,g.id AS gateway_id,sr.site_id FROM site_routes sr JOIN gateways g ON g.site_id=sr.site_id",
    )
    .fetch_all(pool)
    .await?;
    let site_id = Uuid::now_v7();
    let gateway_id = Uuid::now_v7();
    let mut all_routes = Vec::new();
    for row in existing {
        all_routes.push(GatewayRoute {
            gateway_id: parse_uuid(row.try_get::<String, _>("gateway_id")?.as_str(), "gateway")?,
            site_id: parse_uuid(row.try_get::<String, _>("site_id")?.as_str(), "site")?,
            cidr: parse_net(row.try_get::<String, _>("cidr")?.as_str(), "site route")?,
        });
    }
    all_routes.extend(request.routes.iter().copied().map(|cidr| GatewayRoute {
        gateway_id,
        site_id,
        cidr,
    }));
    validate_gateway_routes(ClientPool::new(settings.client_pool)?, &all_routes)?;
    validate_gateway_endpoint_routes(
        pool,
        &all_routes,
        None,
        Some((
            request.endpoint_host.trim(),
            request.public_port.or(request.listen_port).unwrap_or(51_820),
        )),
    )
    .await?;

    let timestamp = now();
    let mut transaction = pool.begin().await?;
    sqlx::query("INSERT INTO sites(id,name,acl_default,created_at,updated_at) VALUES(?,?,?,?,?)")
        .bind(site_id.to_string())
        .bind(request.name.trim())
        .bind(action_name(request.acl_default))
        .bind(&timestamp)
        .bind(&timestamp)
        .execute(&mut *transaction)
        .await?;
    if let Some(agent_id) = request.agent_id {
        let agent_kind: Option<String> =
            sqlx::query_scalar("SELECT kind FROM agents WHERE id=?")
                .bind(agent_id.to_string())
                .fetch_optional(&mut *transaction)
                .await?;
        let agent_kind = agent_kind
            .ok_or_else(|| ApiError::Validation("assigned agent does not exist".into()))?;
        if agent_kind != request.gateway_kind.as_str() {
            return Err(ApiError::Validation(
                "gateway and assigned agent kinds must match".into(),
            ));
        }
    }
    sqlx::query(
        "INSERT INTO gateways(id,site_id,agent_id,kind,status,interface_name,endpoint_host,public_port,listen_port,public_key,compatibility_address,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(gateway_id.to_string())
    .bind(site_id.to_string())
    .bind(request.agent_id.map(|value| value.to_string()))
    .bind(request.gateway_kind.as_str())
    .bind(if request.public_key.is_some() { "ready" } else { "provisioning" })
    .bind(&request.interface_name)
    .bind(request.endpoint_host.trim())
    .bind(request.public_port.map(i64::from))
    .bind(request.listen_port.map(i64::from))
    .bind(request.public_key.as_deref())
    .bind(request.compatibility_address)
    .bind(&timestamp)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    for route in &request.routes {
        sqlx::query("INSERT INTO site_routes(id,site_id,cidr,created_at) VALUES(?,?,?,?)")
            .bind(Uuid::now_v7().to_string())
            .bind(site_id.to_string())
            .bind(route.to_string())
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
    }
    for group_id in &request.granted_group_ids {
        sqlx::query("INSERT INTO site_grants(site_id,group_id,created_at) VALUES(?,?,?)")
            .bind(site_id.to_string())
            .bind(group_id.to_string())
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
    }
    if let Some(public_key) = &request.public_key {
        let result = sqlx::query(
            "INSERT INTO key_registry(id,public_key,owner_kind,owner_id,activated_at) VALUES(?,?,?,?,?)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(public_key)
        .bind("gateway")
        .bind(gateway_id.to_string())
        .bind(&timestamp)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = result {
            if error
                .as_database_error()
                .is_some_and(|database| database.is_unique_violation())
            {
                return Err(ApiError::Conflict("public key is already active".into()));
            }
            return Err(error.into());
        }
    }
    desired::rebuild_gateway(&mut transaction, gateway_id, Vec::new()).await?;
    audit(
        &mut transaction,
        None,
        "system",
        "site.create",
        "site",
        Some(site_id),
        "success",
        serde_json::json!({"gateway_id": gateway_id, "routes": request.routes}),
    )
    .await?;
    transaction.commit().await?;
    get_site(pool, site_id).await
}

fn action_name(action: wiremesh_domain::AclAction) -> &'static str {
    match action {
        wiremesh_domain::AclAction::Allow => "allow",
        wiremesh_domain::AclAction::Deny => "deny",
    }
}

fn parse_action(action: &str) -> Result<wiremesh_domain::AclAction, ApiError> {
    match action {
        "allow" => Ok(wiremesh_domain::AclAction::Allow),
        "deny" => Ok(wiremesh_domain::AclAction::Deny),
        _ => Err(ApiError::Internal(anyhow::anyhow!(
            "invalid ACL action in database"
        ))),
    }
}

pub async fn list_sites(pool: &SqlitePool) -> Result<Vec<SiteResponse>, ApiError> {
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM sites ORDER BY name")
        .fetch_all(pool)
        .await?;
    let mut sites = Vec::with_capacity(ids.len());
    for id in ids {
        sites.push(get_site(pool, parse_uuid(&id, "site")?).await?);
    }
    Ok(sites)
}

pub async fn get_site(pool: &SqlitePool, site_id: Uuid) -> Result<SiteResponse, ApiError> {
    let row = sqlx::query(
        "SELECT s.id,s.name,s.acl_default,g.id AS gateway_id,g.kind,g.status,g.interface_name,
                g.endpoint_host,g.public_port,g.listen_port,g.public_key,g.compatibility_address,
                g.desired_revision,g.applied_revision,g.last_seen_at,g.last_error
         FROM sites s JOIN gateways g ON g.site_id=s.id WHERE s.id=?",
    )
    .bind(site_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("site does not exist".into()))?;
    let routes = sqlx::query_scalar::<_, String>(
        "SELECT cidr FROM site_routes WHERE site_id=? ORDER BY cidr",
    )
    .bind(site_id.to_string())
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|cidr| parse_net(&cidr, "site route"))
    .collect::<Result<Vec<_>, _>>()?;
    let host: String = row.try_get("endpoint_host")?;
    let public_port: Option<i64> = row.try_get("public_port")?;
    let listen_port: Option<i64> = row.try_get("listen_port")?;
    let port = public_port.or(listen_port);
    let granted_group_ids = sqlx::query_scalar::<_, String>(
        "SELECT group_id FROM site_grants WHERE site_id=? ORDER BY group_id",
    )
    .bind(site_id.to_string())
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|value| parse_uuid(&value, "site grant group"))
    .collect::<Result<Vec<_>, _>>()?;
    Ok(SiteResponse {
        id: site_id,
        name: row.try_get("name")?,
        routes,
        acl_default: parse_action(row.try_get::<String, _>("acl_default")?.as_str())?,
        gateway_id: parse_uuid(row.try_get::<String, _>("gateway_id")?.as_str(), "gateway")?,
        gateway_kind: row.try_get("kind")?,
        gateway_status: row.try_get("status")?,
        interface_name: row.try_get("interface_name")?,
        endpoint_host: host.clone(),
        public_port: public_port.map(|value| value as u16),
        listen_port: listen_port.map(|value| value as u16),
        endpoint: port.map(|port| format!("{host}:{port}")),
        public_key: row.try_get("public_key")?,
        compatibility_address: row.try_get("compatibility_address")?,
        granted_group_ids,
        desired_revision: row.try_get::<i64, _>("desired_revision")? as u64,
        applied_revision: row.try_get::<i64, _>("applied_revision")? as u64,
        last_seen_at: row.try_get("last_seen_at")?,
        last_error: row.try_get("last_error")?,
    })
}

pub async fn update_site(
    pool: &SqlitePool,
    site_id: Uuid,
    request: UpdateSiteRequest,
) -> Result<SiteResponse, ApiError> {
    if request.name.trim().is_empty() || request.routes.is_empty() {
        return Err(ApiError::Validation(
            "site name and at least one route are required".into(),
        ));
    }
    if request.endpoint_host.trim().is_empty()
        || request.endpoint_host.chars().any(char::is_whitespace)
    {
        return Err(ApiError::Validation("endpoint host is invalid".into()));
    }
    if request.public_port == Some(0) {
        return Err(ApiError::Validation("gateway port cannot be zero".into()));
    }
    let settings = system_settings(pool).await?;
    let route_rows = sqlx::query(
        "SELECT sr.cidr,g.id AS gateway_id,sr.site_id FROM site_routes sr
         JOIN gateways g ON g.site_id=sr.site_id WHERE sr.site_id != ?",
    )
    .bind(site_id.to_string())
    .fetch_all(pool)
    .await?;
    let gateway = sqlx::query(
        "SELECT id,COALESCE(listen_port,51820) AS listen_port FROM gateways WHERE site_id=?",
    )
        .bind(site_id.to_string())
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::NotFound("site does not exist".into()))?;
    let gateway_id = parse_uuid(&gateway.try_get::<String, _>("id")?, "gateway")?;
    let listen_port = u16::try_from(gateway.try_get::<i64, _>("listen_port")?)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid gateway listen port")))?;
    let mut routes = route_rows
        .into_iter()
        .map(|row| {
            Ok(GatewayRoute {
                gateway_id: parse_uuid(&row.try_get::<String, _>("gateway_id")?, "gateway")?,
                site_id: parse_uuid(&row.try_get::<String, _>("site_id")?, "site")?,
                cidr: parse_net(&row.try_get::<String, _>("cidr")?, "site route")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    routes.extend(request.routes.iter().copied().map(|cidr| GatewayRoute {
        gateway_id,
        site_id,
        cidr,
    }));
    validate_gateway_routes(ClientPool::new(settings.client_pool)?, &routes)?;
    validate_gateway_endpoint_routes(
        pool,
        &routes,
        Some(gateway_id),
        Some((
            request.endpoint_host.trim(),
            request.public_port.unwrap_or(listen_port),
        )),
    )
    .await?;
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    sqlx::query("UPDATE sites SET name=?,acl_default=?,updated_at=? WHERE id=?")
        .bind(request.name.trim())
        .bind(action_name(request.acl_default))
        .bind(&timestamp)
        .bind(site_id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("UPDATE gateways SET endpoint_host=?,public_port=?,compatibility_address=?,updated_at=? WHERE id=?")
        .bind(request.endpoint_host.trim())
        .bind(request.public_port.map(i64::from))
        .bind(request.compatibility_address)
        .bind(&timestamp)
        .bind(gateway_id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM site_routes WHERE site_id=?")
        .bind(site_id.to_string())
        .execute(&mut *transaction)
        .await?;
    for route in &request.routes {
        sqlx::query("INSERT INTO site_routes(id,site_id,cidr,created_at) VALUES(?,?,?,?)")
            .bind(Uuid::now_v7().to_string())
            .bind(site_id.to_string())
            .bind(route.to_string())
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
    }
    sqlx::query("DELETE FROM site_grants WHERE site_id=?")
        .bind(site_id.to_string())
        .execute(&mut *transaction)
        .await?;
    for group_id in &request.granted_group_ids {
        sqlx::query("INSERT INTO site_grants(site_id,group_id,created_at) VALUES(?,?,?)")
            .bind(site_id.to_string())
            .bind(group_id.to_string())
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
    }
    let terminate = all_active_addresses(&mut transaction).await?;
    refresh_all_client_configs(&mut transaction).await?;
    desired::rebuild_gateway(&mut transaction, gateway_id, terminate).await?;
    audit(
        &mut transaction,
        None,
        "system",
        "site.update",
        "site",
        Some(site_id),
        "success",
        serde_json::json!({"routes": request.routes, "groups": request.granted_group_ids}),
    )
    .await?;
    transaction.commit().await?;
    get_site(pool, site_id).await
}

pub async fn get_acl(pool: &SqlitePool, site_id: Uuid) -> Result<AclResponse, ApiError> {
    let default_action: String = sqlx::query_scalar("SELECT acl_default FROM sites WHERE id=?")
        .bind(site_id.to_string())
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::NotFound("site does not exist".into()))?;
    let rows = sqlx::query(
        "SELECT id,position,action,destination,protocol,port_start,port_end,enabled
         FROM acl_rules WHERE site_id=? ORDER BY position,id",
    )
    .bind(site_id.to_string())
    .fetch_all(pool)
    .await?;
    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        let id = parse_uuid(&row.try_get::<String, _>("id")?, "ACL rule")?;
        rules.push(AclRuleModel {
            id: Some(id),
            position: row.try_get::<i64, _>("position")? as u32,
            action: parse_action(&row.try_get::<String, _>("action")?)?,
            destination: parse_net(&row.try_get::<String, _>("destination")?, "ACL destination")?,
            protocol: parse_protocol(&row.try_get::<String, _>("protocol")?)?,
            destination_ports: match (
                row.try_get::<Option<i64>, _>("port_start")?,
                row.try_get::<Option<i64>, _>("port_end")?,
            ) {
                (Some(start), Some(end)) => Some(wiremesh_domain::PortRange {
                    start: start as u16,
                    end: end as u16,
                }),
                _ => None,
            },
            user_ids: sqlx::query_scalar::<_, String>(
                "SELECT user_id FROM acl_rule_users WHERE rule_id=? ORDER BY user_id",
            )
            .bind(id.to_string())
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|value| parse_uuid(&value, "ACL user"))
            .collect::<Result<_, _>>()?,
            group_ids: sqlx::query_scalar::<_, String>(
                "SELECT group_id FROM acl_rule_groups WHERE rule_id=? ORDER BY group_id",
            )
            .bind(id.to_string())
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|value| parse_uuid(&value, "ACL group"))
            .collect::<Result<_, _>>()?,
            enabled: row.try_get("enabled")?,
        });
    }
    Ok(AclResponse {
        default_action: parse_action(&default_action)?,
        rules,
    })
}

pub async fn replace_acl(
    pool: &SqlitePool,
    site_id: Uuid,
    request: ReplaceAclRequest,
) -> Result<AclResponse, ApiError> {
    let mut positions = BTreeSet::new();
    for rule in &request.rules {
        if !positions.insert(rule.position) {
            return Err(ApiError::Validation("ACL positions must be unique".into()));
        }
        if let Some(ports) = &rule.destination_ports {
            if ports.start > ports.end
                || !matches!(rule.protocol, wiremesh_domain::IpProtocol::Tcp | wiremesh_domain::IpProtocol::Udp)
            {
                return Err(ApiError::Validation(
                    "ACL ports require TCP or UDP and an ordered range".into(),
                ));
            }
        }
    }
    let mut transaction = pool.begin().await?;
    let gateway_id: String = sqlx::query_scalar("SELECT id FROM gateways WHERE site_id=?")
        .bind(site_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::NotFound("site does not exist".into()))?;
    sqlx::query("DELETE FROM acl_rules WHERE site_id=?")
        .bind(site_id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("UPDATE sites SET acl_default=?,updated_at=? WHERE id=?")
        .bind(action_name(request.default_action))
        .bind(now())
        .bind(site_id.to_string())
        .execute(&mut *transaction)
        .await?;
    for rule in &request.rules {
        let id = rule.id.unwrap_or_else(Uuid::now_v7);
        sqlx::query(
            "INSERT INTO acl_rules(id,site_id,position,action,destination,protocol,port_start,port_end,enabled,created_at,updated_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(id.to_string())
        .bind(site_id.to_string())
        .bind(i64::from(rule.position))
        .bind(action_name(rule.action))
        .bind(rule.destination.to_string())
        .bind(protocol_name(rule.protocol))
        .bind(rule.destination_ports.as_ref().map(|ports| i64::from(ports.start)))
        .bind(rule.destination_ports.as_ref().map(|ports| i64::from(ports.end)))
        .bind(rule.enabled)
        .bind(now())
        .bind(now())
        .execute(&mut *transaction)
        .await?;
        for user_id in &rule.user_ids {
            sqlx::query("INSERT INTO acl_rule_users(rule_id,user_id) VALUES(?,?)")
                .bind(id.to_string())
                .bind(user_id.to_string())
                .execute(&mut *transaction)
                .await?;
        }
        for group_id in &rule.group_ids {
            sqlx::query("INSERT INTO acl_rule_groups(rule_id,group_id) VALUES(?,?)")
                .bind(id.to_string())
                .bind(group_id.to_string())
                .execute(&mut *transaction)
                .await?;
        }
    }
    let terminate = all_active_addresses(&mut transaction).await?;
    desired::rebuild_gateway(
        &mut transaction,
        parse_uuid(&gateway_id, "gateway")?,
        terminate,
    )
    .await?;
    audit(
        &mut transaction,
        None,
        "system",
        "acl.replace",
        "site",
        Some(site_id),
        "success",
        serde_json::json!({"rules": request.rules.len(), "default": action_name(request.default_action)}),
    )
    .await?;
    transaction.commit().await?;
    get_acl(pool, site_id).await
}

pub async fn create_device(
    pool: &SqlitePool,
    request: CreateDeviceRequest,
) -> Result<DeviceResponse, ApiError> {
    validate_wireguard_public_key(&request.public_key)?;
    if request.name.trim().is_empty() {
        return Err(ApiError::Validation("device name is required".into()));
    }
    let user = get_user(pool, request.user_id).await?;
    if user.disabled {
        return Err(ApiError::Forbidden(
            "disabled users cannot create devices".into(),
        ));
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id=? AND status != 'deleted'")
            .bind(request.user_id.to_string())
            .fetch_one(pool)
            .await?;
    if count >= i64::from(user.device_limit) {
        return Err(ApiError::Conflict("device limit reached".into()));
    }

    let settings = system_settings(pool).await?;
    let pool_definition = ClientPool::new(settings.client_pool)?;
    for attempt in 0..5 {
        match try_create_device(pool, &request, pool_definition, &settings.client_options).await {
            Ok(device) => return Ok(device),
            Err(ApiError::Database(error)) if attempt < 4 && is_retryable_sqlite(&error) => {
                tokio::time::sleep(std::time::Duration::from_millis(20 * (attempt + 1))).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(ApiError::Conflict(
        "could not reserve a unique address".into(),
    ))
}

fn is_retryable_sqlite(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database| {
        database.is_unique_violation() || database.message().contains("locked")
    })
}

async fn try_create_device(
    pool: &SqlitePool,
    request: &CreateDeviceRequest,
    pool_definition: ClientPool,
    options: &ClientOptions,
) -> Result<DeviceResponse, ApiError> {
    let mut transaction = pool.begin().await?;
    let occupied =
        sqlx::query_scalar::<_, String>("SELECT address FROM ip_leases WHERE released_at IS NULL")
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|value| parse_ip(&value, "lease"))
            .collect::<Result<BTreeSet<_>, _>>()?;
    let address = pool_definition.allocate(&occupied)?;
    let timestamp = now();
    let device_id = Uuid::now_v7();
    let result = sqlx::query(
        "INSERT INTO key_registry(id,public_key,owner_kind,owner_id,activated_at) VALUES(?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(&request.public_key)
    .bind("device")
    .bind(device_id.to_string())
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = result {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            return Err(ApiError::Conflict("public key is already active".into()));
        }
        return Err(error.into());
    }
    sqlx::query(
        "INSERT INTO devices(id,user_id,name,public_key,vpn_address,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(device_id.to_string())
    .bind(request.user_id.to_string())
    .bind(request.name.trim())
    .bind(&request.public_key)
    .bind(address.to_string())
    .bind(&timestamp)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("INSERT INTO ip_leases(id,address,device_id,allocated_at) VALUES(?,?,?,?)")
        .bind(Uuid::now_v7().to_string())
        .bind(address.to_string())
        .bind(device_id.to_string())
        .bind(&timestamp)
        .execute(&mut *transaction)
        .await?;
    let model = build_config(
        &mut transaction,
        device_id,
        request.user_id,
        request.name.trim(),
        address,
        1,
        options.clone(),
    )
    .await?;
    store_snapshot(&mut transaction, &model).await?;
    audit(
        &mut transaction,
        Some(request.user_id),
        "user",
        "device.create",
        "device",
        Some(device_id),
        "success",
        serde_json::json!({"address": address, "public_key": request.public_key}),
    )
    .await?;
    desired::rebuild_gateways_for_user(&mut transaction, request.user_id, Vec::new()).await?;
    transaction.commit().await?;
    get_device(pool, device_id).await
}

async fn build_config(
    transaction: &mut Transaction<'_, Sqlite>,
    device_id: Uuid,
    user_id: Uuid,
    device_name: &str,
    address: Ipv4Addr,
    revision: u64,
    options: ClientOptions,
) -> Result<ClientConfigModel, ApiError> {
    let rows = sqlx::query(
        "SELECT DISTINCT s.id,s.name,g.endpoint_host,g.public_port,g.listen_port,g.public_key
         FROM site_grants sg
         JOIN effective_group_memberships gm ON gm.group_id=sg.group_id
         JOIN sites s ON s.id=sg.site_id
         JOIN gateways g ON g.site_id=s.id
         WHERE gm.user_id=? AND g.public_key IS NOT NULL
         ORDER BY s.name",
    )
    .bind(user_id.to_string())
    .fetch_all(&mut **transaction)
    .await?;
    let mut peers = Vec::new();
    for row in rows {
        let site_id = parse_uuid(row.try_get::<String, _>("id")?.as_str(), "site")?;
        let routes = sqlx::query_scalar::<_, String>(
            "SELECT cidr FROM site_routes WHERE site_id=? ORDER BY cidr",
        )
        .bind(site_id.to_string())
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|value| parse_net(&value, "site route"))
        .collect::<Result<Vec<_>, _>>()?;
        let host: String = row.try_get("endpoint_host")?;
        let port: Option<i64> = row
            .try_get::<Option<i64>, _>("public_port")?
            .or(row.try_get::<Option<i64>, _>("listen_port")?);
        let Some(port) = port else { continue };
        peers.push(ClientPeer {
            site_id,
            site_name: row.try_get("name")?,
            public_key: row.try_get("public_key")?,
            endpoint: format!("{host}:{port}"),
            allowed_ips: routes,
        });
    }
    Ok(ClientConfigModel {
        device_id,
        device_name: device_name.into(),
        revision,
        address,
        options,
        peers,
    })
}

async fn store_snapshot(
    transaction: &mut Transaction<'_, Sqlite>,
    model: &ClientConfigModel,
) -> Result<(), ApiError> {
    model.validate()?;
    sqlx::query(
        "INSERT INTO config_snapshots(device_id,revision,fingerprint,model_json,created_at) VALUES(?,?,?,?,?)",
    )
    .bind(model.device_id.to_string())
    .bind(model.revision as i64)
    .bind(model.fingerprint())
    .bind(serde_json::to_string(model).map_err(|error| ApiError::Internal(error.into()))?)
    .bind(now())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub async fn list_devices(pool: &SqlitePool) -> Result<Vec<DeviceResponse>, ApiError> {
    let ids = sqlx::query_scalar::<_, String>("SELECT id FROM devices ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?;
    let mut devices = Vec::with_capacity(ids.len());
    for id in ids {
        devices.push(get_device(pool, parse_uuid(&id, "device")?).await?);
    }
    Ok(devices)
}

pub async fn list_devices_for_user(
    pool: &SqlitePool,
    user_id: Uuid,
) -> Result<Vec<DeviceResponse>, ApiError> {
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM devices WHERE user_id=? ORDER BY created_at DESC",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    let mut devices = Vec::with_capacity(ids.len());
    for id in ids {
        devices.push(get_device(pool, parse_uuid(&id, "device")?).await?);
    }
    Ok(devices)
}

pub async fn get_device(pool: &SqlitePool, id: Uuid) -> Result<DeviceResponse, ApiError> {
    let row = sqlx::query(
        "SELECT id,user_id,name,public_key,vpn_address,status,config_revision,acknowledged_revision,created_at FROM devices WHERE id=?",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("device does not exist".into()))?;
    let config_revision = row.try_get::<i64, _>("config_revision")? as u64;
    let acknowledged_revision = row.try_get::<i64, _>("acknowledged_revision")? as u64;
    Ok(DeviceResponse {
        id,
        user_id: parse_uuid(row.try_get::<String, _>("user_id")?.as_str(), "user")?,
        name: row.try_get("name")?,
        public_key: row.try_get("public_key")?,
        vpn_address: parse_ip(row.try_get::<String, _>("vpn_address")?.as_str(), "device")?,
        status: row.try_get("status")?,
        config_revision,
        acknowledged_revision,
        outdated: config_revision != acknowledged_revision,
        created_at: row.try_get("created_at")?,
    })
}

pub async fn device_config(pool: &SqlitePool, id: Uuid) -> Result<DeviceConfigResponse, ApiError> {
    let device = get_device(pool, id).await?;
    let current_json: String = sqlx::query_scalar(
        "SELECT model_json FROM config_snapshots WHERE device_id=? AND revision=?",
    )
    .bind(id.to_string())
    .bind(device.config_revision as i64)
    .fetch_one(pool)
    .await?;
    let model: ClientConfigModel =
        serde_json::from_str(&current_json).map_err(|error| ApiError::Internal(error.into()))?;
    let changes = if device.acknowledged_revision == 0 {
        model
            .peers
            .iter()
            .map(|peer| wiremesh_domain::ConfigChange {
                kind: wiremesh_domain::ConfigChangeKind::PeerAdded,
                site_id: Some(peer.site_id),
                description: format!("site {} is available", peer.site_name),
            })
            .collect()
    } else {
        let old_json: Option<String> = sqlx::query_scalar(
            "SELECT model_json FROM config_snapshots WHERE device_id=? AND revision=?",
        )
        .bind(id.to_string())
        .bind(device.acknowledged_revision as i64)
        .fetch_optional(pool)
        .await?;
        old_json
            .map(|json| serde_json::from_str::<ClientConfigModel>(&json))
            .transpose()
            .map_err(|error| ApiError::Internal(error.into()))?
            .map(|old| old.diff(&model))
            .unwrap_or_default()
    };
    // Provisioning status is intentionally based on every authorized site,
    // not only peers that are already renderable. A newly assigned or offline
    // gateway may not have reported its public key yet, but users still need to
    // see that access as pending rather than as if the grant did not exist.
    let site_rows = sqlx::query(
        "SELECT DISTINCT s.id,s.name,g.status,g.desired_revision,g.applied_revision,
                g.last_seen_at,g.last_error,g.public_key,
                COALESCE(g.public_port,g.listen_port) AS endpoint_port
         FROM site_grants sg
         JOIN effective_group_memberships gm ON gm.group_id=sg.group_id
         JOIN sites s ON s.id=sg.site_id
         JOIN gateways g ON g.site_id=s.id
         WHERE gm.user_id=?
         ORDER BY s.name",
    )
    .bind(device.user_id.to_string())
    .fetch_all(pool)
    .await?;
    let mut peer_statuses = Vec::with_capacity(site_rows.len());
    for row in site_rows {
        let last_error: Option<String> = row.try_get("last_error")?;
        let gateway_status: String = row.try_get("status")?;
        let has_renderable_peer = row.try_get::<Option<String>, _>("public_key")?.is_some()
            && row.try_get::<Option<i64>, _>("endpoint_port")?.is_some();
        let (state, error) = if gateway_status == "error" || last_error.is_some() {
            ("error".into(), last_error)
        } else {
            let desired = row.try_get::<i64, _>("desired_revision")?;
            let applied = row.try_get::<i64, _>("applied_revision")?;
            let fresh = row
                .try_get::<Option<String>, _>("last_seen_at")?
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|value| value > Utc::now() - chrono::Duration::seconds(45));
            if applied >= desired && fresh && has_renderable_peer {
                ("ready".into(), None)
            } else {
                ("pending".into(), None)
            }
        };
        peer_statuses.push(PeerProvisioningResponse {
            site_id: parse_uuid(&row.try_get::<String, _>("id")?, "site")?,
            site_name: row.try_get("name")?,
            state,
            error,
        });
    }
    Ok(DeviceConfigResponse {
        placeholder_config: model.render(None),
        model,
        acknowledged_revision: device.acknowledged_revision,
        outdated: device.outdated,
        changes,
        peer_statuses,
    })
}

pub async fn acknowledge_config(
    pool: &SqlitePool,
    id: Uuid,
    request: AcknowledgeConfigRequest,
) -> Result<DeviceResponse, ApiError> {
    let device = get_device(pool, id).await?;
    if request.revision != device.config_revision {
        return Err(ApiError::Conflict(format!(
            "revision {} is no longer current",
            request.revision
        )));
    }
    sqlx::query(
        "UPDATE devices SET acknowledged_revision=?,acknowledgement_method=?,acknowledged_at=?,updated_at=? WHERE id=?",
    )
    .bind(request.revision as i64)
    .bind(request.method.as_str())
    .bind(now())
    .bind(now())
    .bind(id.to_string())
    .execute(pool)
    .await?;
    append_audit(
        pool,
        "device.config_acknowledge",
        "device",
        Some(id),
        serde_json::json!({"revision": request.revision, "method": request.method.as_str()}),
    )
    .await?;
    get_device(pool, id).await
}

pub async fn rotate_device_key(
    pool: &SqlitePool,
    id: Uuid,
    request: RotateDeviceKeyRequest,
) -> Result<DeviceResponse, ApiError> {
    validate_wireguard_public_key(&request.public_key)?;
    let device = get_device(pool, id).await?;
    if device.status != "active" {
        return Err(ApiError::Conflict(
            "only active devices can rotate keys".into(),
        ));
    }
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    let gateway_ids = desired::gateway_ids_that_may_hold_device(&mut transaction, id).await?;
    let result = sqlx::query(
        "INSERT INTO key_registry(id,public_key,owner_kind,owner_id,activated_at) VALUES(?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(&request.public_key)
    .bind("device")
    .bind(id.to_string())
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = result {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            return Err(ApiError::Conflict("public key is already active".into()));
        }
        return Err(error.into());
    }
    let old_key_id: String = sqlx::query_scalar(
        "SELECT id FROM key_registry WHERE owner_kind='device' AND owner_id=? AND retired_at IS NULL AND public_key=?",
    )
    .bind(id.to_string())
    .bind(&device.public_key)
    .fetch_one(&mut *transaction)
    .await?;
    let revision = device.config_revision + 1;
    sqlx::query("UPDATE devices SET public_key=?,config_revision=?,updated_at=? WHERE id=?")
        .bind(&request.public_key)
        .bind(revision as i64)
        .bind(&timestamp)
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    let previous_json: String = sqlx::query_scalar(
        "SELECT model_json FROM config_snapshots WHERE device_id=? AND revision=?",
    )
    .bind(id.to_string())
    .bind(device.config_revision as i64)
    .fetch_one(&mut *transaction)
    .await?;
    let mut model: ClientConfigModel =
        serde_json::from_str(&previous_json).map_err(|error| ApiError::Internal(error.into()))?;
    model.revision = revision;
    store_snapshot(&mut transaction, &model).await?;
    audit(
        &mut transaction,
        Some(device.user_id),
        "user",
        "device.key_rotate",
        "device",
        Some(id),
        "success",
        serde_json::json!({"revision": revision}),
    )
    .await?;
    let states = desired::rebuild_gateways(
        &mut transaction,
        gateway_ids,
        vec![device.vpn_address],
    )
    .await?;
    for state in &states {
        sqlx::query(
            "INSERT INTO key_gateway_acks(key_id,gateway_id,required_revision) VALUES(?,?,?)",
        )
        .bind(&old_key_id)
        .bind(state.gateway_id.to_string())
        .bind(state.revision as i64)
        .execute(&mut *transaction)
        .await?;
    }
    if states.is_empty() {
        sqlx::query("UPDATE key_registry SET retired_at=? WHERE id=?")
            .bind(&timestamp)
            .bind(&old_key_id)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    get_device(pool, id).await
}

pub async fn delete_device(pool: &SqlitePool, id: Uuid) -> Result<(), ApiError> {
    let device = get_device(pool, id).await?;
    if device.status == "deleted" {
        return Ok(());
    }
    let timestamp = now();
    let mut transaction = pool.begin().await?;
    let gateway_ids = desired::gateway_ids_that_may_hold_device(&mut transaction, id).await?;
    sqlx::query("UPDATE devices SET status='deleted',deleted_at=?,updated_at=? WHERE id=?")
        .bind(&timestamp)
        .bind(&timestamp)
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    let lease_id: String =
        sqlx::query_scalar("SELECT id FROM ip_leases WHERE device_id=? AND released_at IS NULL")
            .bind(id.to_string())
            .fetch_one(&mut *transaction)
            .await?;
    sqlx::query("UPDATE ip_leases SET quarantined_at=? WHERE id=?")
        .bind(&timestamp)
        .bind(&lease_id)
        .execute(&mut *transaction)
        .await?;
    let old_key_id: String = sqlx::query_scalar(
        "SELECT id FROM key_registry WHERE owner_kind='device' AND owner_id=? AND retired_at IS NULL AND public_key=?",
    )
    .bind(id.to_string())
    .bind(&device.public_key)
    .fetch_one(&mut *transaction)
    .await?;
    let states = desired::rebuild_gateways(
        &mut transaction,
        gateway_ids,
        vec![device.vpn_address],
    )
    .await?;
    for state in &states {
        sqlx::query(
            "INSERT INTO lease_gateway_acks(lease_id,gateway_id,required_revision) VALUES(?,?,?)",
        )
        .bind(&lease_id)
        .bind(state.gateway_id.to_string())
        .bind(state.revision as i64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO key_gateway_acks(key_id,gateway_id,required_revision) VALUES(?,?,?)",
        )
        .bind(&old_key_id)
        .bind(state.gateway_id.to_string())
        .bind(state.revision as i64)
        .execute(&mut *transaction)
        .await?;
    }
    if states.is_empty() {
        sqlx::query("UPDATE ip_leases SET released_at=? WHERE id=?")
            .bind(&timestamp)
            .bind(&lease_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("UPDATE key_registry SET retired_at=? WHERE owner_kind='device' AND owner_id=? AND retired_at IS NULL")
            .bind(&timestamp)
            .bind(id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    audit(
        &mut transaction,
        Some(device.user_id),
        "user",
        "device.delete",
        "device",
        Some(id),
        "success",
        serde_json::json!({
            "pending_gateways": states.iter().map(|state| state.gateway_id).collect::<Vec<_>>()
        }),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn set_user_device_limit(
    pool: &SqlitePool,
    user_id: Uuid,
    limit: Option<u32>,
) -> Result<UserResponse, ApiError> {
    if limit == Some(0) || limit.is_some_and(|value| value > 100) {
        return Err(ApiError::Validation(
            "device limit must be between 1 and 100".into(),
        ));
    }
    let result = sqlx::query("UPDATE users SET device_limit_override=?,updated_at=? WHERE id=?")
        .bind(limit.map(i64::from))
        .bind(now())
        .bind(user_id.to_string())
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("user does not exist".into()));
    }
    append_audit(
        pool,
        "user.device_limit",
        "user",
        Some(user_id),
        serde_json::json!({"limit": limit}),
    )
    .await?;
    get_user(pool, user_id).await
}

pub async fn update_system_settings(
    pool: &SqlitePool,
    request: UpdateSystemSettingsRequest,
) -> Result<SystemSettingsResponse, ApiError> {
    if request.default_device_limit == 0 || request.default_device_limit > 100 {
        return Err(ApiError::Validation(
            "default device limit must be between 1 and 100".into(),
        ));
    }
    validate_client_options(&request.client_options)?;
    let current = system_settings(pool).await?;
    let old_pool = ClientPool::new(current.client_pool)?;
    let new_pool = ClientPool::new(request.client_pool)?;
    if old_pool != new_pool {
        old_pool.validate_expansion(new_pool)?;
    }
    let route_rows = sqlx::query(
        "SELECT sr.cidr,g.id AS gateway_id,sr.site_id FROM site_routes sr JOIN gateways g ON g.site_id=sr.site_id",
    )
    .fetch_all(pool)
    .await?;
    let routes = route_rows
        .into_iter()
        .map(|row| {
            Ok(GatewayRoute {
                gateway_id: parse_uuid(&row.try_get::<String, _>("gateway_id")?, "gateway")?,
                site_id: parse_uuid(&row.try_get::<String, _>("site_id")?, "site")?,
                cidr: parse_net(&row.try_get::<String, _>("cidr")?, "site route")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    validate_gateway_routes(new_pool, &routes)?;
    validate_gateway_endpoint_routes(pool, &routes, None, None).await?;

    let timestamp = now();
    let mut transaction = pool.begin().await?;
    for (key, value) in [
        (
            "client_pool",
            serde_json::to_string(&request.client_pool.to_string())
                .map_err(|error| ApiError::Internal(error.into()))?,
        ),
        (
            "default_device_limit",
            serde_json::to_string(&request.default_device_limit)
                .map_err(|error| ApiError::Internal(error.into()))?,
        ),
        (
            "client_options",
            serde_json::to_string(&request.client_options)
                .map_err(|error| ApiError::Internal(error.into()))?,
        ),
    ] {
        sqlx::query("UPDATE system_settings SET value_json=?,updated_at=? WHERE key=?")
            .bind(value)
            .bind(&timestamp)
            .bind(key)
            .execute(&mut *transaction)
            .await?;
    }
    refresh_all_client_configs(&mut transaction).await?;
    desired::rebuild_all_gateways(&mut transaction, Vec::new()).await?;
    audit(
        &mut transaction,
        None,
        "system",
        "system.settings.update",
        "system",
        None,
        "success",
        serde_json::json!({
            "client_pool": request.client_pool,
            "default_device_limit": request.default_device_limit,
            "client_options": request.client_options,
        }),
    )
    .await?;
    transaction.commit().await?;
    system_settings(pool).await
}

pub async fn list_audit_events(
    pool: &SqlitePool,
    limit: u32,
) -> Result<Vec<AuditEventResponse>, ApiError> {
    let limit = limit.clamp(1, 500);
    let rows = sqlx::query(
        "SELECT id,occurred_at,actor_user_id,actor_kind,action,object_kind,object_id,outcome,details_json
         FROM audit_events ORDER BY occurred_at DESC,id DESC LIMIT ?",
    )
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(AuditEventResponse {
                id: parse_uuid(&row.try_get::<String, _>("id")?, "audit event")?,
                occurred_at: row.try_get("occurred_at")?,
                actor_user_id: row
                    .try_get::<Option<String>, _>("actor_user_id")?
                    .map(|value| parse_uuid(&value, "audit actor"))
                    .transpose()?,
                actor_kind: row.try_get("actor_kind")?,
                action: row.try_get("action")?,
                object_kind: row.try_get("object_kind")?,
                object_id: row.try_get("object_id")?,
                outcome: row.try_get("outcome")?,
                details: serde_json::from_str(&row.try_get::<String, _>("details_json")?)
                    .map_err(|error| ApiError::Internal(error.into()))?,
            })
        })
        .collect()
}

pub(crate) async fn refresh_all_client_configs(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<usize, ApiError> {
    let user_ids = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT user_id FROM devices WHERE status != 'deleted' ORDER BY user_id",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|value| parse_uuid(&value, "user"))
    .collect::<Result<Vec<_>, _>>()?;
    let mut changed = 0;
    for user_id in user_ids {
        changed += refresh_user_configs(transaction, user_id).await?;
    }
    Ok(changed)
}

pub(crate) async fn refresh_user_configs(
    transaction: &mut Transaction<'_, Sqlite>,
    user_id: Uuid,
) -> Result<usize, ApiError> {
    let options = client_options_in_transaction(transaction).await?;
    let rows = sqlx::query(
        "SELECT id,name,vpn_address,config_revision FROM devices
         WHERE user_id=? AND status != 'deleted' ORDER BY id",
    )
    .bind(user_id.to_string())
    .fetch_all(&mut **transaction)
    .await?;
    let mut changed = 0;
    let mut access_changed = false;
    for row in rows {
        let device_id = parse_uuid(&row.try_get::<String, _>("id")?, "device")?;
        let current_revision = row.try_get::<i64, _>("config_revision")? as u64;
        let candidate = build_config(
            transaction,
            device_id,
            user_id,
            &row.try_get::<String, _>("name")?,
            parse_ip(&row.try_get::<String, _>("vpn_address")?, "device")?,
            current_revision + 1,
            options.clone(),
        )
        .await?;
        let current = sqlx::query(
            "SELECT fingerprint,model_json FROM config_snapshots WHERE device_id=? AND revision=?",
        )
        .bind(device_id.to_string())
        .bind(current_revision as i64)
        .fetch_one(&mut **transaction)
        .await?;
        let current_fingerprint: String = current.try_get("fingerprint")?;
        if candidate.fingerprint() != current_fingerprint {
            let current_model: ClientConfigModel =
                serde_json::from_str(&current.try_get::<String, _>("model_json")?)
                    .map_err(|error| ApiError::Internal(error.into()))?;
            access_changed |= current_model.diff(&candidate).iter().any(|change| {
                matches!(
                    change.kind,
                    ConfigChangeKind::PeerAdded | ConfigChangeKind::PeerRemoved
                )
            });
            store_snapshot(transaction, &candidate).await?;
            sqlx::query("UPDATE devices SET config_revision=?,updated_at=? WHERE id=?")
                .bind(candidate.revision as i64)
                .bind(now())
                .bind(device_id.to_string())
                .execute(&mut **transaction)
                .await?;
            changed += 1;
        }
    }
    if changed > 0 {
        queue_profile_notification(transaction, user_id, changed, access_changed).await?;
    }
    Ok(changed)
}

async fn queue_profile_notification(
    transaction: &mut Transaction<'_, Sqlite>,
    user_id: Uuid,
    changed_devices: usize,
    access_changed: bool,
) -> Result<(), ApiError> {
    let template = if access_changed {
        "access_change"
    } else {
        "profile_change"
    };
    let timestamp = now();
    sqlx::query(
        "INSERT INTO mail_jobs(id,recipient,template,parameters_json,next_attempt_at,created_at)
         SELECT ?,u.email,?,?,?,? FROM users u
         WHERE u.id=?
           AND EXISTS(SELECT 1 FROM smtp_settings s WHERE s.singleton=1 AND s.enabled=1)
           AND NOT EXISTS(
             SELECT 1 FROM mail_jobs pending
             WHERE pending.recipient=u.email AND pending.template=?
               AND pending.status IN ('pending','sending')
           )",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(template)
    .bind(
        serde_json::json!({"user_id": user_id, "changed_devices": changed_devices}).to_string(),
    )
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(user_id.to_string())
    .bind(template)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn client_options_in_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<ClientOptions, ApiError> {
    let json: String = sqlx::query_scalar(
        "SELECT value_json FROM system_settings WHERE key='client_options'",
    )
    .fetch_one(&mut **transaction)
    .await?;
    serde_json::from_str(&json).map_err(|error| ApiError::Internal(error.into()))
}

pub(crate) async fn active_addresses_for_user(
    transaction: &mut Transaction<'_, Sqlite>,
    user_id: Uuid,
) -> Result<Vec<Ipv4Addr>, ApiError> {
    sqlx::query_scalar::<_, String>(
        "SELECT vpn_address FROM devices WHERE user_id=? AND status='active'",
    )
    .bind(user_id.to_string())
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|value| parse_ip(&value, "device"))
    .collect()
}

pub(crate) async fn all_active_addresses(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<Vec<Ipv4Addr>, ApiError> {
    sqlx::query_scalar::<_, String>("SELECT vpn_address FROM devices WHERE status='active'")
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|value| parse_ip(&value, "device"))
        .collect()
}

fn validate_client_options(options: &ClientOptions) -> Result<(), ApiError> {
    if options
        .search_domains
        .iter()
        .any(|domain| domain.is_empty() || domain.chars().any(char::is_whitespace))
    {
        return Err(ApiError::Validation("DNS search domains are invalid".into()));
    }
    if options.mtu.is_some_and(|mtu| !(576..=9_000).contains(&mtu)) {
        return Err(ApiError::Validation("MTU must be between 576 and 9000".into()));
    }
    if options.persistent_keepalive == Some(0) {
        return Err(ApiError::Validation(
            "PersistentKeepalive must be omitted or non-zero".into(),
        ));
    }
    Ok(())
}

fn protocol_name(protocol: wiremesh_domain::IpProtocol) -> &'static str {
    match protocol {
        wiremesh_domain::IpProtocol::Any => "any",
        wiremesh_domain::IpProtocol::Tcp => "tcp",
        wiremesh_domain::IpProtocol::Udp => "udp",
        wiremesh_domain::IpProtocol::Icmp => "icmp",
    }
}

fn parse_protocol(protocol: &str) -> Result<wiremesh_domain::IpProtocol, ApiError> {
    match protocol {
        "any" => Ok(wiremesh_domain::IpProtocol::Any),
        "tcp" => Ok(wiremesh_domain::IpProtocol::Tcp),
        "udp" => Ok(wiremesh_domain::IpProtocol::Udp),
        "icmp" => Ok(wiremesh_domain::IpProtocol::Icmp),
        _ => Err(ApiError::Internal(anyhow::anyhow!(
            "invalid ACL protocol in database"
        ))),
    }
}

async fn append_audit(
    pool: &SqlitePool,
    action: &str,
    object_kind: &str,
    object_id: Option<Uuid>,
    details: serde_json::Value,
) -> Result<(), ApiError> {
    let mut transaction = pool.begin().await?;
    audit(
        &mut transaction,
        None,
        "system",
        action,
        object_kind,
        object_id,
        "success",
        details,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn audit(
    transaction: &mut Transaction<'_, Sqlite>,
    actor_user_id: Option<Uuid>,
    actor_kind: &str,
    action: &str,
    object_kind: &str,
    object_id: Option<Uuid>,
    outcome: &str,
    details: serde_json::Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_events(id,occurred_at,actor_user_id,actor_kind,action,object_kind,object_id,outcome,details_json) VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(now())
    .bind(actor_user_id.map(|id| id.to_string()))
    .bind(actor_kind)
    .bind(action)
    .bind(object_kind)
    .bind(object_id.map(|id| id.to_string()))
    .bind(outcome)
    .bind(details.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::*;

    async fn test_pool() -> SqlitePool {
        let options = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    fn key(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    #[tokio::test]
    async fn creates_users_and_unique_device_leases() {
        let pool = test_pool().await;
        let user = create_user(
            &pool,
            CreateUserRequest {
                email: "Person@Example.com".into(),
                name: "Person".into(),
                title: "".into(),
            },
        )
        .await
        .unwrap();
        let first = create_device(
            &pool,
            CreateDeviceRequest {
                user_id: user.id,
                name: "phone".into(),
                public_key: key(1),
            },
        )
        .await
        .unwrap();
        let second = create_device(
            &pool,
            CreateDeviceRequest {
                user_id: user.id,
                name: "laptop".into(),
                public_key: key(2),
            },
        )
        .await
        .unwrap();
        assert_ne!(first.vpn_address, second.vpn_address);
        assert_eq!(first.vpn_address, "10.20.0.2".parse::<Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn profile_download_acknowledges_placeholder_revision() {
        let pool = test_pool().await;
        let user = create_user(
            &pool,
            CreateUserRequest {
                email: "person@example.com".into(),
                name: "Person".into(),
                title: "".into(),
            },
        )
        .await
        .unwrap();
        let device = create_device(
            &pool,
            CreateDeviceRequest {
                user_id: user.id,
                name: "phone".into(),
                public_key: key(3),
            },
        )
        .await
        .unwrap();
        let config = device_config(&pool, device.id).await.unwrap();
        assert!(config.placeholder_config.contains("<CLIENT_PRIVATE_KEY>"));
        let acknowledged = acknowledge_config(
            &pool,
            device.id,
            AcknowledgeConfigRequest {
                revision: 1,
                method: crate::models::AcknowledgementMethod::PlaceholderDownload,
            },
        )
        .await
        .unwrap();
        assert!(!acknowledged.outdated);
    }

    #[tokio::test]
    async fn purge_waits_for_removal_and_releases_the_email() {
        let pool = test_pool().await;
        let user = create_user(
            &pool,
            CreateUserRequest {
                email: "departed@example.com".into(),
                name: "Departed".into(),
                title: "".into(),
            },
        )
        .await
        .unwrap();
        create_device(
            &pool,
            CreateDeviceRequest {
                user_id: user.id,
                name: "phone".into(),
                public_key: key(8),
            },
        )
        .await
        .unwrap();
        let deleted = soft_delete_user(&pool, user.id).await.unwrap();
        assert!(deleted.soft_deleted);
        let purged = purge_user(&pool, user.id).await.unwrap();
        assert!(purged.purged);
        assert!(list_devices_for_user(&pool, user.id).await.unwrap().is_empty());
        assert!(create_user(
            &pool,
            CreateUserRequest {
                email: "departed@example.com".into(),
                name: "Replacement".into(),
                title: "".into(),
            },
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn audit_rows_cannot_be_changed_or_deleted() {
        let pool = test_pool().await;
        create_user(
            &pool,
            CreateUserRequest {
                email: "audit@example.com".into(),
                name: "Audit".into(),
                title: String::new(),
            },
        )
        .await
        .unwrap();
        assert!(sqlx::query("UPDATE audit_events SET outcome='failed'")
            .execute(&pool)
            .await
            .is_err());
        assert!(sqlx::query("DELETE FROM audit_events")
            .execute(&pool)
            .await
            .is_err());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}
