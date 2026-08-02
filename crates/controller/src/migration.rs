use std::{collections::{BTreeMap, BTreeSet}, net::Ipv4Addr};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;
use wiremesh_agent_core::state_hash;
use wiremesh_domain::{ClientPool, DesiredGatewayState, GatewayRoute, validate_gateway_routes};

use crate::{
    error::ApiError,
    models::{CreateSubnetMigrationRequest, SubnetMigrationResponse},
    service,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressMove {
    pub device_id: Uuid,
    pub old_address: Ipv4Addr,
    pub new_address: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FutureGateway {
    pub base_revision: u64,
    pub state: DesiredGatewayState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub addresses: Vec<AddressMove>,
    pub gateways: BTreeMap<Uuid, FutureGateway>,
}

pub async fn create(
    pool: &SqlitePool,
    actor: Uuid,
    request: CreateSubnetMigrationRequest,
) -> Result<SubnetMigrationResponse, ApiError> {
    let effective_at = DateTime::parse_from_rfc3339(&request.effective_at)
        .map_err(|_| ApiError::Validation("effective_at must be an RFC 3339 timestamp".into()))?
        .with_timezone(&Utc);
    if effective_at <= Utc::now() + chrono::Duration::seconds(30) {
        return Err(ApiError::Validation(
            "migration must be scheduled at least 30 seconds in the future".into(),
        ));
    }
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subnet_migrations WHERE status IN ('preparing','armed')",
    )
    .fetch_one(pool)
    .await?;
    if active > 0 {
        return Err(ApiError::Conflict(
            "another subnet migration is already active".into(),
        ));
    }
    let settings = service::system_settings(pool).await?;
    let old_pool = ClientPool::new(settings.client_pool)?;
    let new_pool = ClientPool::new(request.new_pool)?;
    if old_pool == new_pool {
        return Err(ApiError::Validation("new pool is unchanged".into()));
    }
    if old_pool.validate_expansion(new_pool).is_ok() {
        return Err(ApiError::Validation(
            "containing-supernet changes are in-place expansions, not hard migrations".into(),
        ));
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
                gateway_id: parse_uuid(&row.try_get::<String, _>("gateway_id")?)?,
                site_id: parse_uuid(&row.try_get::<String, _>("site_id")?)?,
                cidr: row
                    .try_get::<String, _>("cidr")?
                    .parse()
                    .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid route: {error}")))?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    validate_gateway_routes(new_pool, &routes)?;
    let device_rows = sqlx::query(
        "SELECT id,vpn_address FROM devices WHERE status != 'deleted' ORDER BY vpn_address,id",
    )
    .fetch_all(pool)
    .await?;
    let mut occupied = BTreeSet::new();
    let mut addresses = Vec::with_capacity(device_rows.len());
    for row in device_rows {
        let new_address = new_pool.allocate(&occupied)?;
        occupied.insert(new_address);
        addresses.push(AddressMove {
            device_id: parse_uuid(&row.try_get::<String, _>("id")?)?,
            old_address: row
                .try_get::<String, _>("vpn_address")?
                .parse()
                .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid device address: {error}")))?,
            new_address,
        });
    }
    let mapping: BTreeMap<Uuid, Ipv4Addr> = addresses
        .iter()
        .map(|movement| (movement.device_id, movement.new_address))
        .collect();
    let state_rows = sqlx::query(
        "SELECT g.id,g.kind,g.compatibility_address,g.desired_revision,ds.state_json
         FROM gateways g JOIN gateway_desired_states ds ON ds.gateway_id=g.id AND ds.revision=g.desired_revision
         ORDER BY g.id",
    )
    .fetch_all(pool)
    .await?;
    let mut gateways = BTreeMap::new();
    for row in state_rows {
        let gateway_id = parse_uuid(&row.try_get::<String, _>("id")?)?;
        let base_revision = row.try_get::<i64, _>("desired_revision")? as u64;
        let mut state: DesiredGatewayState = serde_json::from_str(&row.try_get::<String, _>("state_json")?)
            .map_err(|error| ApiError::Internal(error.into()))?;
        state.revision = base_revision + 1;
        state.terminate_sources = addresses.iter().map(|move_| move_.old_address).collect();
        for peer in &mut state.peers {
            if let Some(address) = mapping.get(&peer.device_id) {
                peer.allowed_address = *address;
            }
        }
        if row.try_get::<String, _>("kind")? == "mikrotik"
            && row.try_get::<bool, _>("compatibility_address")?
        {
            state.compatibility_address = Some(new_pool.compatibility_address());
        }
        state.canonicalize();
        gateways.insert(gateway_id, FutureGateway { base_revision, state });
    }
    let plan = MigrationPlan { addresses, gateways };
    let id = Uuid::now_v7();
    let timestamp = Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO subnet_migrations(id,old_pool,new_pool,effective_at,status,plan_json,created_by,created_at,updated_at)
         VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(old_pool.cidr.to_string())
    .bind(new_pool.cidr.to_string())
    .bind(effective_at.to_rfc3339())
    .bind("preparing")
    .bind(serde_json::to_string(&plan).map_err(|error| ApiError::Internal(error.into()))?)
    .bind(actor.to_string())
    .bind(&timestamp)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    for (gateway_id, future) in &plan.gateways {
        sqlx::query(
            "INSERT INTO subnet_migration_gateways(migration_id,gateway_id,base_revision,future_revision,expected_state_hash)
             VALUES(?,?,?,?,?)",
        )
        .bind(id.to_string())
        .bind(gateway_id.to_string())
        .bind(future.base_revision as i64)
        .bind(future.state.revision as i64)
        .bind(state_hash(&future.state))
        .execute(&mut *transaction)
        .await?;
    }
    insert_audit(&mut transaction, actor, "subnet_migration.create", id).await?;
    transaction.commit().await?;
    get(pool, id).await
}

pub async fn arm(
    pool: &SqlitePool,
    actor: Uuid,
    migration_id: Uuid,
) -> Result<SubnetMigrationResponse, ApiError> {
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT status,effective_at,old_pool,plan_json FROM subnet_migrations WHERE id=?",
    )
        .bind(migration_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::NotFound("migration does not exist".into()))?;
    if row.try_get::<String, _>("status")? != "preparing" {
        return Err(ApiError::Conflict("migration is not preparing".into()));
    }
    let plan: MigrationPlan = serde_json::from_str(&row.try_get::<String, _>("plan_json")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    validate_plan_source(
        &mut transaction,
        &plan,
        &row.try_get::<String, _>("old_pool")?,
    )
    .await?;
    let missing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subnet_migration_gateways WHERE migration_id=? AND prepared_at IS NULL",
    )
    .bind(migration_id.to_string())
    .fetch_one(&mut *transaction)
    .await?;
    if missing > 0 {
        return Err(ApiError::Conflict(format!(
            "{missing} gateway(s) have not validated the future state"
        )));
    }
    let drifted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subnet_migration_gateways mg JOIN gateways g ON g.id=mg.gateway_id
         WHERE mg.migration_id=? AND g.desired_revision != mg.base_revision",
    )
    .bind(migration_id.to_string())
    .fetch_one(&mut *transaction)
    .await?;
    if drifted > 0 {
        return Err(ApiError::Conflict(
            "gateway state changed after preparation; cancel and create a new migration".into(),
        ));
    }
    let effective = DateTime::parse_from_rfc3339(&row.try_get::<String, _>("effective_at")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    if effective <= Utc::now() {
        return Err(ApiError::Conflict("migration effective time has passed".into()));
    }
    sqlx::query("UPDATE subnet_migrations SET status='armed',updated_at=? WHERE id=?")
        .bind(Utc::now().to_rfc3339())
        .bind(migration_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let recipients = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT u.email FROM users u JOIN devices d ON d.user_id=u.id
         WHERE d.status != 'deleted' AND u.soft_deleted_at IS NULL",
    )
    .fetch_all(&mut *transaction)
    .await?;
    let timestamp = Utc::now().to_rfc3339();
    for recipient in recipients {
        sqlx::query(
            "INSERT INTO mail_jobs(id,recipient,template,parameters_json,next_attempt_at,created_at)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(recipient)
        .bind("pool_migration")
        .bind(
            serde_json::json!({"migration_id": migration_id, "effective_at": effective})
                .to_string(),
        )
        .bind(&timestamp)
        .bind(&timestamp)
        .execute(&mut *transaction)
        .await?;
    }
    insert_audit(&mut transaction, actor, "subnet_migration.arm", migration_id).await?;
    transaction.commit().await?;
    get(pool, migration_id).await
}

pub async fn cancel(
    pool: &SqlitePool,
    actor: Uuid,
    migration_id: Uuid,
) -> Result<(), ApiError> {
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "UPDATE subnet_migrations SET status='cancelled',updated_at=? WHERE id=? AND status='preparing'",
    )
    .bind(Utc::now().to_rfc3339())
    .bind(migration_id.to_string())
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict(
            "only a preparing migration can be cancelled".into(),
        ));
    }
    insert_audit(&mut transaction, actor, "subnet_migration.cancel", migration_id).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn record_prepared(
    pool: &SqlitePool,
    migration_id: Uuid,
    gateway_id: Uuid,
    revision: u64,
    hash: &str,
) -> Result<(), ApiError> {
    let expected = sqlx::query(
        "SELECT future_revision,expected_state_hash FROM subnet_migration_gateways WHERE migration_id=? AND gateway_id=?",
    )
    .bind(migration_id.to_string())
    .bind(gateway_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("migration gateway preparation does not exist".into()))?;
    if expected.try_get::<i64, _>("future_revision")? as u64 != revision
        || expected.try_get::<String, _>("expected_state_hash")? != hash
    {
        return Err(ApiError::Conflict(
            "agent prepared state does not match the migration plan".into(),
        ));
    }
    sqlx::query(
        "UPDATE subnet_migration_gateways SET prepared_state_hash=?,prepared_at=? WHERE migration_id=? AND gateway_id=?",
    )
    .bind(hash)
    .bind(Utc::now().to_rfc3339())
    .bind(migration_id.to_string())
    .bind(gateway_id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn apply_due(pool: &SqlitePool) -> Result<usize, ApiError> {
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM subnet_migrations WHERE status='armed' AND effective_at<=? ORDER BY effective_at",
    )
    .bind(Utc::now().to_rfc3339())
    .fetch_all(pool)
    .await?;
    let mut applied = 0;
    for id in ids {
        let migration_id = parse_uuid(&id)?;
        match apply_one(pool, migration_id).await {
            Ok(()) => applied += 1,
            Err(error) => {
                tracing::error!(%migration_id, %error, "scheduled subnet migration could not be applied");
            }
        }
    }
    Ok(applied)
}

async fn apply_one(pool: &SqlitePool, migration_id: Uuid) -> Result<(), ApiError> {
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT old_pool,new_pool,plan_json FROM subnet_migrations WHERE id=? AND status='armed'",
    )
        .bind(migration_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::Conflict("migration is no longer armed".into()))?;
    let new_pool: Ipv4Net = row.try_get::<String, _>("new_pool")?.parse()
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid migration pool: {error}")))?;
    let plan: MigrationPlan = serde_json::from_str(&row.try_get::<String, _>("plan_json")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    if let Err(error) = validate_plan_source(
        &mut transaction,
        &plan,
        &row.try_get::<String, _>("old_pool")?,
    )
    .await
    {
        sqlx::query("UPDATE subnet_migrations SET status='failed',updated_at=? WHERE id=?")
            .bind(Utc::now().to_rfc3339())
            .bind(migration_id.to_string())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        return Err(error);
    }
    let drifted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subnet_migration_gateways mg JOIN gateways g ON g.id=mg.gateway_id
         WHERE mg.migration_id=? AND g.desired_revision != mg.base_revision",
    )
    .bind(migration_id.to_string())
    .fetch_one(&mut *transaction)
    .await?;
    if drifted > 0 {
        sqlx::query("UPDATE subnet_migrations SET status='failed',updated_at=? WHERE id=?")
            .bind(Utc::now().to_rfc3339())
            .bind(migration_id.to_string())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        return Err(ApiError::Conflict("migration failed because gateway state drifted".into()));
    }
    sqlx::query("UPDATE system_settings SET value_json=?,updated_at=? WHERE key='client_pool'")
        .bind(serde_json::to_string(&new_pool.to_string()).map_err(|error| ApiError::Internal(error.into()))?)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await?;

    // Free all live address uniqueness constraints before assigning the final
    // addresses. This also supports partially overlapping old and new pools
    // where one device receives an address previously held by another device.
    for movement in &plan.addresses {
        sqlx::query("UPDATE ip_leases SET address=? WHERE device_id=? AND released_at IS NULL")
            .bind(format!("migration:{migration_id}:{}", movement.device_id))
            .bind(movement.device_id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    for movement in &plan.addresses {
        sqlx::query("UPDATE devices SET vpn_address=?,updated_at=? WHERE id=?")
            .bind(movement.new_address.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(movement.device_id.to_string())
            .execute(&mut *transaction)
            .await?;
        sqlx::query("UPDATE ip_leases SET address=? WHERE device_id=? AND released_at IS NULL")
            .bind(movement.new_address.to_string())
            .bind(movement.device_id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    for (gateway_id, future) in &plan.gateways {
        sqlx::query(
            "INSERT INTO gateway_desired_states(gateway_id,revision,state_json,state_hash,created_at) VALUES(?,?,?,?,?)",
        )
        .bind(gateway_id.to_string())
        .bind(future.state.revision as i64)
        .bind(serde_json::to_string(&future.state).map_err(|error| ApiError::Internal(error.into()))?)
        .bind(state_hash(&future.state))
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE gateways SET desired_revision=?,updated_at=? WHERE id=?")
            .bind(future.state.revision as i64)
            .bind(Utc::now().to_rfc3339())
            .bind(gateway_id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    service::refresh_all_client_configs(&mut transaction).await?;
    sqlx::query("UPDATE subnet_migrations SET status='applied',updated_at=? WHERE id=?")
        .bind(Utc::now().to_rfc3339())
        .bind(migration_id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO audit_events(id,occurred_at,actor_kind,action,object_kind,object_id,outcome,details_json)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(Utc::now().to_rfc3339())
    .bind("scheduler")
    .bind("subnet_migration.apply")
    .bind("subnet_migration")
    .bind(migration_id.to_string())
    .bind("success")
    .bind("{}")
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn get(pool: &SqlitePool, migration_id: Uuid) -> Result<SubnetMigrationResponse, ApiError> {
    let row = sqlx::query(
        "SELECT id,old_pool,new_pool,effective_at,status,plan_json FROM subnet_migrations WHERE id=?",
    )
    .bind(migration_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("migration does not exist".into()))?;
    response_from_row(pool, row).await
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<SubnetMigrationResponse>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,old_pool,new_pool,effective_at,status,plan_json FROM subnet_migrations ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows { result.push(response_from_row(pool, row).await?); }
    Ok(result)
}

async fn response_from_row(pool: &SqlitePool, row: sqlx::sqlite::SqliteRow) -> Result<SubnetMigrationResponse, ApiError> {
    let id = parse_uuid(&row.try_get::<String, _>("id")?)?;
    let plan: MigrationPlan = serde_json::from_str(&row.try_get::<String, _>("plan_json")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let total_gateways: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subnet_migration_gateways WHERE migration_id=?")
        .bind(id.to_string()).fetch_one(pool).await?;
    let prepared_gateways: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subnet_migration_gateways WHERE migration_id=? AND prepared_at IS NOT NULL")
        .bind(id.to_string()).fetch_one(pool).await?;
    Ok(SubnetMigrationResponse {
        id,
        old_pool: row.try_get::<String, _>("old_pool")?.parse().map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid pool: {error}")))?,
        new_pool: row.try_get::<String, _>("new_pool")?.parse().map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid pool: {error}")))?,
        effective_at: row.try_get("effective_at")?,
        status: row.try_get("status")?,
        prepared_gateways,
        total_gateways,
        affected_devices: plan.addresses.len(),
    })
}

async fn insert_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    actor: Uuid,
    action: &str,
    migration_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_events(id,occurred_at,actor_user_id,actor_kind,action,object_kind,object_id,outcome,details_json)
         VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(Utc::now().to_rfc3339())
    .bind(actor.to_string())
    .bind("user")
    .bind(action)
    .bind("subnet_migration")
    .bind(migration_id.to_string())
    .bind("success")
    .bind("{}")
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn validate_plan_source(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    plan: &MigrationPlan,
    expected_pool: &str,
) -> Result<(), ApiError> {
    let current_pool_json: String = sqlx::query_scalar(
        "SELECT value_json FROM system_settings WHERE key='client_pool'",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let current_pool: String = serde_json::from_str(&current_pool_json)
        .map_err(|error| ApiError::Internal(error.into()))?;
    if current_pool != expected_pool {
        return Err(ApiError::Conflict(
            "client pool changed after this migration was planned".into(),
        ));
    }
    let rows = sqlx::query("SELECT id,vpn_address FROM devices WHERE status != 'deleted'")
        .fetch_all(&mut **transaction)
        .await?;
    if rows.len() != plan.addresses.len() {
        return Err(ApiError::Conflict(
            "device set changed after this migration was planned".into(),
        ));
    }
    let planned: BTreeMap<Uuid, Ipv4Addr> = plan
        .addresses
        .iter()
        .map(|movement| (movement.device_id, movement.old_address))
        .collect();
    for row in rows {
        let id = parse_uuid(&row.try_get::<String, _>("id")?)?;
        let address: Ipv4Addr = row
            .try_get::<String, _>("vpn_address")?
            .parse()
            .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid device address: {error}")))?;
        if planned.get(&id) != Some(&address) {
            return Err(ApiError::Conflict(
                "device addresses changed after this migration was planned".into(),
            ));
        }
    }
    Ok(())
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    value.parse().map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid UUID: {error}")))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use base64::{Engine, engine::general_purpose::STANDARD};
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;
    use crate::models::{CreateDeviceRequest, CreateUserRequest};

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

    #[tokio::test]
    async fn scheduled_hard_migration_moves_leases_and_profiles_atomically() {
        let pool = pool().await;
        let user = service::create_user(
            &pool,
            CreateUserRequest {
                email: "migration@example.com".into(),
                name: "Migration".into(),
                title: String::new(),
            },
        )
        .await
        .unwrap();
        let device = service::create_device(
            &pool,
            CreateDeviceRequest {
                user_id: user.id,
                name: "laptop".into(),
                public_key: STANDARD.encode([44_u8; 32]),
            },
        )
        .await
        .unwrap();
        let plan = create(
            &pool,
            user.id,
            CreateSubnetMigrationRequest {
                new_pool: "10.30.0.0/16".parse().unwrap(),
                effective_at: (Utc::now() + chrono::Duration::seconds(31)).to_rfc3339(),
            },
        )
        .await
        .unwrap();
        arm(&pool, user.id, plan.id).await.unwrap();
        sqlx::query("UPDATE subnet_migrations SET effective_at=? WHERE id=?")
            .bind((Utc::now() - chrono::Duration::seconds(1)).to_rfc3339())
            .bind(plan.id.to_string())
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(apply_due(&pool).await.unwrap(), 1);
        let moved = service::get_device(&pool, device.id).await.unwrap();
        assert_eq!(moved.vpn_address, "10.30.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(service::system_settings(&pool).await.unwrap().client_pool, "10.30.0.0/16".parse::<Ipv4Net>().unwrap());
        assert!(moved.config_revision > device.config_revision);
    }
}
