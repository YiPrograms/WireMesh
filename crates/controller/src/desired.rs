use std::{collections::BTreeSet, net::Ipv4Addr};

use ipnet::Ipv4Net;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;
use wiremesh_agent_core::state_hash;
use wiremesh_domain::{
    AclAction, AclRule, AclSubjects, DesiredGatewayState, DesiredPeer, IpProtocol, PortRange,
};

use crate::error::ApiError;

pub async fn rebuild_gateway(
    transaction: &mut Transaction<'_, Sqlite>,
    gateway_id: Uuid,
    terminate_sources: Vec<Ipv4Addr>,
) -> Result<DesiredGatewayState, ApiError> {
    let active_migration: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subnet_migrations WHERE status IN ('preparing','armed')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if active_migration > 0 {
        return Err(ApiError::Conflict(
            "configuration changes are paused during an active subnet migration".into(),
        ));
    }
    let gateway = sqlx::query(
        "SELECT g.site_id,g.interface_name,g.listen_port,g.desired_revision,g.kind,g.compatibility_address,s.acl_default
         FROM gateways g JOIN sites s ON s.id=g.site_id WHERE g.id=?",
    )
    .bind(gateway_id.to_string())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| ApiError::NotFound("gateway does not exist".into()))?;
    let site_id = parse_uuid(&gateway.try_get::<String, _>("site_id")?, "site")?;
    let revision = gateway.try_get::<i64, _>("desired_revision")? as u64 + 1;
    let routes = sqlx::query_scalar::<_, String>(
        "SELECT cidr FROM site_routes WHERE site_id=? ORDER BY cidr",
    )
    .bind(site_id.to_string())
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|value| parse_net(&value, "site route"))
    .collect::<Result<Vec<_>, _>>()?;

    let peer_rows = sqlx::query(
        "SELECT DISTINCT d.id,d.user_id,d.public_key,d.vpn_address
         FROM devices d JOIN users u ON u.id=d.user_id
         WHERE d.status='active' AND u.manual_disabled=0 AND u.ldap_disabled=0
           AND u.soft_deleted_at IS NULL
           AND EXISTS (
             SELECT 1 FROM site_grants sg
             JOIN effective_group_memberships gm ON gm.group_id=sg.group_id
             WHERE sg.site_id=? AND gm.user_id=d.user_id
           )
           ORDER BY d.vpn_address",
    )
    .bind(site_id.to_string())
    .fetch_all(&mut **transaction)
    .await?;
    let mut peers = Vec::with_capacity(peer_rows.len());
    for row in peer_rows {
        let user_id = parse_uuid(&row.try_get::<String, _>("user_id")?, "user")?;
        peers.push(DesiredPeer {
            device_id: parse_uuid(&row.try_get::<String, _>("id")?, "device")?,
            user_id,
            public_key: row.try_get("public_key")?,
            allowed_address: row
                .try_get::<String, _>("vpn_address")?
                .parse()
                .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid VPN address: {error}")))?,
            group_ids: effective_group_ids(transaction, user_id).await?,
        });
    }

    let rule_rows = sqlx::query(
        "SELECT id,position,action,destination,protocol,port_start,port_end,enabled
         FROM acl_rules WHERE site_id=? ORDER BY position,id",
    )
    .bind(site_id.to_string())
    .fetch_all(&mut **transaction)
    .await?;
    let mut acl_rules = Vec::with_capacity(rule_rows.len());
    for row in rule_rows {
        let id = parse_uuid(&row.try_get::<String, _>("id")?, "ACL rule")?;
        let users = sqlx::query_scalar::<_, String>(
            "SELECT user_id FROM acl_rule_users WHERE rule_id=? ORDER BY user_id",
        )
        .bind(id.to_string())
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|value| parse_uuid(&value, "ACL user"))
        .collect::<Result<BTreeSet<_>, _>>()?;
        let groups = sqlx::query_scalar::<_, String>(
            "SELECT group_id FROM acl_rule_groups WHERE rule_id=? ORDER BY group_id",
        )
        .bind(id.to_string())
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|value| parse_uuid(&value, "ACL group"))
        .collect::<Result<BTreeSet<_>, _>>()?;
        let start: Option<i64> = row.try_get("port_start")?;
        let end: Option<i64> = row.try_get("port_end")?;
        let destination_ports = match (start, end) {
            (None, None) => None,
            (Some(start), Some(end)) if (0..=65_535).contains(&start) && start <= end => {
                Some(PortRange {
                    start: start as u16,
                    end: end as u16,
                })
            }
            _ => {
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "invalid ACL port range in database"
                )));
            }
        };
        acl_rules.push(AclRule {
            id,
            position: row.try_get::<i64, _>("position")? as u32,
            action: parse_action(&row.try_get::<String, _>("action")?)?,
            destination: parse_net(&row.try_get::<String, _>("destination")?, "ACL destination")?,
            protocol: parse_protocol(&row.try_get::<String, _>("protocol")?)?,
            destination_ports,
            subjects: AclSubjects { users, groups },
            enabled: row.try_get("enabled")?,
        });
    }

    let mtu = setting_client_mtu(transaction).await?;
    let compatibility_address = if gateway.try_get::<bool, _>("compatibility_address")?
        && gateway.try_get::<String, _>("kind")? == "mikrotik"
    {
        Some(setting_client_pool(transaction).await?.hosts().next().ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("client pool has no compatibility address"))
        })?)
    } else {
        None
    };
    let mut state = DesiredGatewayState {
        gateway_id,
        revision,
        interface_name: gateway.try_get("interface_name")?,
        listen_port: gateway
            .try_get::<Option<i64>, _>("listen_port")?
            .unwrap_or(51_820) as u16,
        mtu,
        compatibility_address,
        routes,
        peers,
        acl_default: parse_action(&gateway.try_get::<String, _>("acl_default")?)?,
        acl_rules,
        terminate_sources,
    };
    state.canonicalize();
    let encoded = serde_json::to_string(&state)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
    let hash = state_hash(&state);
    sqlx::query(
        "INSERT INTO gateway_desired_states(gateway_id,revision,state_json,state_hash,created_at) VALUES(?,?,?,?,?)",
    )
    .bind(gateway_id.to_string())
    .bind(revision as i64)
    .bind(encoded)
    .bind(hash)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE gateways SET desired_revision=?,updated_at=? WHERE id=?",
    )
    .bind(revision as i64)
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(gateway_id.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(state)
}

pub async fn rebuild_gateways_for_user(
    transaction: &mut Transaction<'_, Sqlite>,
    user_id: Uuid,
    terminate_sources: Vec<Ipv4Addr>,
) -> Result<Vec<DesiredGatewayState>, ApiError> {
    ensure_no_active_migration(transaction).await?;
    let ids = gateway_ids_for_user(transaction, user_id).await?;
    let mut states = Vec::with_capacity(ids.len());
    for id in ids {
        states.push(rebuild_gateway(transaction, id, terminate_sources.clone()).await?);
    }
    Ok(states)
}

/// Returns gateways whose last acknowledged state, or any newer state that may
/// have been applied without an acknowledgement, contains this device. Desired
/// state history is retained, so this remains safe across access revocation and
/// controller/agent disconnects.
pub async fn gateway_ids_that_may_hold_device(
    transaction: &mut Transaction<'_, Sqlite>,
    device_id: Uuid,
) -> Result<Vec<Uuid>, ApiError> {
    let rows = sqlx::query(
        "SELECT g.id,ds.state_json FROM gateways g
         JOIN gateway_desired_states ds ON ds.gateway_id=g.id
         WHERE ds.revision>=g.applied_revision ORDER BY g.id,ds.revision",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut ids = BTreeSet::new();
    for row in rows {
        let state: DesiredGatewayState =
            serde_json::from_str(&row.try_get::<String, _>("state_json")?)
                .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
        if state.peers.iter().any(|peer| peer.device_id == device_id) {
            ids.insert(parse_uuid(&row.try_get::<String, _>("id")?, "gateway")?);
        }
    }
    Ok(ids.into_iter().collect())
}

pub async fn rebuild_gateways(
    transaction: &mut Transaction<'_, Sqlite>,
    gateway_ids: impl IntoIterator<Item = Uuid>,
    terminate_sources: Vec<Ipv4Addr>,
) -> Result<Vec<DesiredGatewayState>, ApiError> {
    ensure_no_active_migration(transaction).await?;
    let ids: BTreeSet<_> = gateway_ids.into_iter().collect();
    let mut states = Vec::with_capacity(ids.len());
    for id in ids {
        states.push(rebuild_gateway(transaction, id, terminate_sources.clone()).await?);
    }
    Ok(states)
}

pub async fn rebuild_all_gateways(
    transaction: &mut Transaction<'_, Sqlite>,
    terminate_sources: Vec<Ipv4Addr>,
) -> Result<Vec<DesiredGatewayState>, ApiError> {
    ensure_no_active_migration(transaction).await?;
    let ids = sqlx::query_scalar::<_, String>("SELECT id FROM gateways ORDER BY id")
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|value| parse_uuid(&value, "gateway"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut states = Vec::with_capacity(ids.len());
    for id in ids {
        states.push(rebuild_gateway(transaction, id, terminate_sources.clone()).await?);
    }
    Ok(states)
}

async fn ensure_no_active_migration(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<(), ApiError> {
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subnet_migrations WHERE status IN ('preparing','armed')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if active > 0 {
        Err(ApiError::Conflict(
            "configuration changes are paused during an active subnet migration".into(),
        ))
    } else {
        Ok(())
    }
}

pub async fn gateway_ids_for_user(
    transaction: &mut Transaction<'_, Sqlite>,
    user_id: Uuid,
) -> Result<Vec<Uuid>, ApiError> {
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT g.id FROM gateways g
         JOIN site_grants sg ON sg.site_id=g.site_id
         JOIN effective_group_memberships gm ON gm.group_id=sg.group_id
         WHERE gm.user_id=?
         ORDER BY g.id",
    )
    .bind(user_id.to_string())
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|value| parse_uuid(&value, "gateway"))
    .collect()
}

pub async fn latest_states_for_agent(
    pool: &SqlitePool,
    agent_id: Uuid,
) -> Result<Vec<DesiredGatewayState>, ApiError> {
    let rows = sqlx::query(
        "SELECT ds.state_json FROM gateways g
         JOIN gateway_desired_states ds ON ds.gateway_id=g.id AND ds.revision=g.desired_revision
         WHERE g.agent_id=? ORDER BY g.id",
    )
    .bind(agent_id.to_string())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            serde_json::from_str::<DesiredGatewayState>(&row.try_get::<String, _>("state_json")?)
                .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))
        })
        .collect()
}

pub async fn record_applied(
    pool: &SqlitePool,
    gateway_id: Uuid,
    revision: u64,
    actual_state_hash: &str,
) -> Result<(), ApiError> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await?;
    let desired: Option<i64> = sqlx::query_scalar("SELECT desired_revision FROM gateways WHERE id=?")
        .bind(gateway_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(desired) = desired else {
        return Err(ApiError::NotFound("gateway does not exist".into()));
    };
    if revision > desired as u64 {
        return Err(ApiError::Conflict("agent acknowledged an unknown future revision".into()));
    }
    sqlx::query(
        "UPDATE gateways SET applied_revision=MAX(applied_revision,?),actual_state_hash=?,status='ready',last_error=NULL,last_seen_at=?,updated_at=? WHERE id=?",
    )
    .bind(revision as i64)
    .bind(actual_state_hash)
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(gateway_id.to_string())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO gateway_apply_events(id,gateway_id,revision,outcome,state_hash,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(gateway_id.to_string())
    .bind(revision as i64)
    .bind("applied")
    .bind(actual_state_hash)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE lease_gateway_acks SET acknowledged_at=? WHERE gateway_id=? AND required_revision<=? AND acknowledged_at IS NULL",
    )
    .bind(&timestamp)
    .bind(gateway_id.to_string())
    .bind(revision as i64)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE key_gateway_acks SET acknowledged_at=? WHERE gateway_id=? AND required_revision<=? AND acknowledged_at IS NULL",
    )
    .bind(&timestamp)
    .bind(gateway_id.to_string())
    .bind(revision as i64)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE user_deletion_gateway_acks SET acknowledged_at=?
         WHERE gateway_id=? AND required_revision<=? AND acknowledged_at IS NULL",
    )
    .bind(&timestamp)
    .bind(gateway_id.to_string())
    .bind(revision as i64)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE ip_leases SET released_at=?
         WHERE quarantined_at IS NOT NULL AND released_at IS NULL
           AND NOT EXISTS(SELECT 1 FROM lease_gateway_acks a WHERE a.lease_id=ip_leases.id AND a.acknowledged_at IS NULL)",
    )
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE key_registry SET retired_at=?
         WHERE retired_at IS NULL
           AND EXISTS(SELECT 1 FROM key_gateway_acks a WHERE a.key_id=key_registry.id)
           AND NOT EXISTS(SELECT 1 FROM key_gateway_acks a WHERE a.key_id=key_registry.id AND a.acknowledged_at IS NULL)",
    )
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    crate::service::audit(
        &mut transaction,
        None,
        "agent",
        "gateway.reconcile.applied",
        "gateway",
        Some(gateway_id),
        "success",
        serde_json::json!({"revision": revision, "actual_state_hash": actual_state_hash}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn record_error(
    pool: &SqlitePool,
    gateway_id: Uuid,
    revision: u64,
    code: &str,
    message: &str,
) -> Result<(), ApiError> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await?;
    sqlx::query("UPDATE gateways SET status='error',last_error=?,last_seen_at=?,updated_at=? WHERE id=?")
        .bind(message)
        .bind(&timestamp)
        .bind(&timestamp)
        .bind(gateway_id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO gateway_apply_events(id,gateway_id,revision,outcome,error_code,error_message,created_at) VALUES(?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(gateway_id.to_string())
    .bind(revision as i64)
    .bind("error")
    .bind(code)
    .bind(message)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    crate::service::audit(
        &mut transaction,
        None,
        "agent",
        "gateway.reconcile.error",
        "gateway",
        Some(gateway_id),
        "failure",
        serde_json::json!({"revision": revision, "code": code, "message": message}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn effective_group_ids(
    transaction: &mut Transaction<'_, Sqlite>,
    user_id: Uuid,
) -> Result<BTreeSet<Uuid>, ApiError> {
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT gm.group_id FROM effective_group_memberships gm
         WHERE gm.user_id=?",
    )
    .bind(user_id.to_string())
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|value| parse_uuid(&value, "group"))
    .collect()
}

async fn setting_client_mtu(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<Option<u16>, ApiError> {
    let json: String = sqlx::query_scalar(
        "SELECT value_json FROM system_settings WHERE key='client_options'",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let options: wiremesh_domain::ClientOptions = serde_json::from_str(&json)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
    Ok(options.mtu)
}

async fn setting_client_pool(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<Ipv4Net, ApiError> {
    let json: String = sqlx::query_scalar(
        "SELECT value_json FROM system_settings WHERE key='client_pool'",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let value: String = serde_json::from_str(&json)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
    parse_net(&value, "client pool")
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid {field} UUID: {error}")))
}

fn parse_net(value: &str, field: &str) -> Result<Ipv4Net, ApiError> {
    value
        .parse()
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid {field}: {error}")))
}

fn parse_action(value: &str) -> Result<AclAction, ApiError> {
    match value {
        "allow" => Ok(AclAction::Allow),
        "deny" => Ok(AclAction::Deny),
        _ => Err(ApiError::Internal(anyhow::anyhow!("invalid ACL action"))),
    }
}

fn parse_protocol(value: &str) -> Result<IpProtocol, ApiError> {
    match value {
        "any" => Ok(IpProtocol::Any),
        "tcp" => Ok(IpProtocol::Tcp),
        "udp" => Ok(IpProtocol::Udp),
        "icmp" => Ok(IpProtocol::Icmp),
        _ => Err(ApiError::Internal(anyhow::anyhow!("invalid ACL protocol"))),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    #[tokio::test]
    async fn device_exposure_follows_acknowledged_and_newer_state_history() {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let gateway_id = Uuid::now_v7();
        let site_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let timestamp = chrono::Utc::now().to_rfc3339();
        sqlx::query("INSERT INTO sites(id,name,created_at,updated_at) VALUES(?,?,?,?)")
            .bind(site_id.to_string())
            .bind("branch")
            .bind(&timestamp)
            .bind(&timestamp)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO gateways(id,site_id,kind,interface_name,endpoint_host,desired_revision,applied_revision,created_at,updated_at)
             VALUES(?,?,'linux','wg-wiremesh','vpn.example.com',2,1,?,?)",
        )
        .bind(gateway_id.to_string())
        .bind(site_id.to_string())
        .bind(&timestamp)
        .bind(&timestamp)
        .execute(&pool)
        .await
        .unwrap();

        let present = DesiredGatewayState {
            gateway_id,
            revision: 1,
            interface_name: "wg-wiremesh".into(),
            listen_port: 51_820,
            mtu: None,
            compatibility_address: None,
            routes: Vec::new(),
            peers: vec![DesiredPeer {
                device_id,
                user_id: Uuid::now_v7(),
                public_key: "test-key".into(),
                allowed_address: "10.20.0.2".parse().unwrap(),
                group_ids: BTreeSet::new(),
            }],
            acl_default: AclAction::Allow,
            acl_rules: Vec::new(),
            terminate_sources: Vec::new(),
        };
        let mut removed = present.clone();
        removed.revision = 2;
        removed.peers.clear();
        for state in [&present, &removed] {
            sqlx::query(
                "INSERT INTO gateway_desired_states(gateway_id,revision,state_json,state_hash,created_at)
                 VALUES(?,?,?,?,?)",
            )
            .bind(gateway_id.to_string())
            .bind(state.revision as i64)
            .bind(serde_json::to_string(state).unwrap())
            .bind(state_hash(state))
            .bind(&timestamp)
            .execute(&pool)
            .await
            .unwrap();
        }

        let mut transaction = pool.begin().await.unwrap();
        assert_eq!(
            gateway_ids_that_may_hold_device(&mut transaction, device_id)
                .await
                .unwrap(),
            vec![gateway_id]
        );
        transaction.rollback().await.unwrap();

        sqlx::query("UPDATE gateways SET applied_revision=2 WHERE id=?")
            .bind(gateway_id.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let mut transaction = pool.begin().await.unwrap();
        assert!(
            gateway_ids_that_may_hold_device(&mut transaction, device_id)
                .await
                .unwrap()
                .is_empty()
        );
        transaction.rollback().await.unwrap();
    }
}
