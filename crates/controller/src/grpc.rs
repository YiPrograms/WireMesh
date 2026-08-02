use std::{collections::HashMap, net::SocketAddr, pin::Pin, time::Duration};

use futures::{Stream, StreamExt};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Request, Response, Status,
    transport::{Identity, Server, ServerTlsConfig},
};
use uuid::Uuid;
use wiremesh_agent_core::protocol::desired_to_proto;
use wiremesh_proto::{PROTOCOL_MAJOR, PROTOCOL_MINOR, v1 as proto};

use crate::{desired, error::ApiError, migration, router_target, secrets::SecretBox, service};

#[derive(Clone)]
pub struct AgentService {
    pool: SqlitePool,
    secrets: SecretBox,
}

impl AgentService {
    pub fn new(pool: SqlitePool, secrets: SecretBox) -> Self {
        Self { pool, secrets }
    }
}

type ResponseStream = Pin<Box<dyn Stream<Item = Result<proto::ControllerMessage, Status>> + Send>>;

#[tonic::async_trait]
impl proto::agent_control_server::AgentControl for AgentService {
    type SynchronizeStream = ResponseStream;

    async fn synchronize(
        &self,
        request: Request<tonic::Streaming<proto::AgentMessage>>,
    ) -> Result<Response<Self::SynchronizeStream>, Status> {
        let secret = bearer_secret(request.metadata())?.to_owned();
        let mut incoming = request.into_inner();
        let first = tokio::time::timeout(Duration::from_secs(10), incoming.next())
            .await
            .map_err(|_| Status::deadline_exceeded("agent hello timed out"))?
            .ok_or_else(|| Status::invalid_argument("agent hello is required"))??;
        let hello = match first.payload {
            Some(proto::agent_message::Payload::Hello(hello)) => hello,
            _ => return Err(Status::invalid_argument("first agent message must be hello")),
        };
        if hello.protocol_major != PROTOCOL_MAJOR {
            return Err(Status::failed_precondition(format!(
                "protocol major {} is unsupported; controller requires {}",
                hello.protocol_major, PROTOCOL_MAJOR
            )));
        }
        let agent_id: Uuid = hello
            .agent_id
            .parse()
            .map_err(|_| Status::invalid_argument("hello contains an invalid agent ID"))?;
        authenticate_agent(&self.pool, agent_id, &secret).await?;
        register_hello(&self.pool, agent_id, &hello).await?;

        let (sender, receiver) = mpsc::channel::<Result<proto::ControllerMessage, Status>>(32);
        let pool = self.pool.clone();
        let secrets = self.secrets.clone();
        tokio::spawn(async move {
            if let Err(error) = drive_connection(pool, secrets, agent_id, incoming, sender.clone()).await {
                tracing::warn!(%agent_id, error = %error, "agent stream ended with an error");
                let _ = sender.send(Err(error)).await;
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

pub async fn serve(
    pool: SqlitePool,
    secrets: SecretBox,
    listen: SocketAddr,
    certificate_path: &std::path::Path,
    private_key_path: &std::path::Path,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let certificate = tokio::fs::read(certificate_path).await?;
    let private_key = tokio::fs::read(private_key_path).await?;
    let identity = Identity::from_pem(certificate, private_key);
    tracing::info!(%listen, "WireMesh agent gRPC endpoint listening with TLS");
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(proto::agent_control_server::AgentControlServer::new(
            AgentService::new(pool, secrets),
        ))
        .serve_with_shutdown(listen, async move {
            let _ = shutdown.recv().await;
        })
        .await?;
    Ok(())
}

async fn drive_connection(
    pool: SqlitePool,
    secrets: SecretBox,
    agent_id: Uuid,
    mut incoming: tonic::Streaming<proto::AgentMessage>,
    sender: mpsc::Sender<Result<proto::ControllerMessage, Status>>,
) -> Result<(), Status> {
    let mut sent_revisions = HashMap::<Uuid, u64>::new();
    let mut sent_migrations = HashMap::<(Uuid, Uuid), String>::new();
    send_new_states(&pool, &secrets, agent_id, &sender, &mut sent_revisions).await?;
    send_migrations(
        &pool,
        &secrets,
        agent_id,
        &sender,
        &mut sent_migrations,
        &mut sent_revisions,
    )
    .await?;
    let mut refresh = tokio::time::interval(Duration::from_secs(5));
    let mut ping_count = 0_u8;
    loop {
        tokio::select! {
            _ = refresh.tick() => {
                send_new_states(&pool, &secrets, agent_id, &sender, &mut sent_revisions).await?;
                send_migrations(
                    &pool,
                    &secrets,
                    agent_id,
                    &sender,
                    &mut sent_migrations,
                    &mut sent_revisions,
                ).await?;
                ping_count = ping_count.wrapping_add(1);
                if ping_count % 3 == 0 {
                    sender.send(Ok(proto::ControllerMessage {
                        payload: Some(proto::controller_message::Payload::Ping(proto::Ping {
                            unix_seconds: chrono::Utc::now().timestamp(),
                        })),
                    })).await.map_err(|_| Status::cancelled("agent disconnected"))?;
                }
            }
            message = incoming.next() => {
                let Some(message) = message else { return Ok(()); };
                handle_message(&pool, agent_id, message?).await?;
            }
        }
    }
}

async fn send_migrations(
    pool: &SqlitePool,
    secrets: &SecretBox,
    agent_id: Uuid,
    sender: &mpsc::Sender<Result<proto::ControllerMessage, Status>>,
    sent: &mut HashMap<(Uuid, Uuid), String>,
    sent_revisions: &mut HashMap<Uuid, u64>,
) -> Result<(), Status> {
    let rows = sqlx::query(
        "SELECT m.id,m.status,m.effective_at,m.plan_json,mg.gateway_id
         FROM subnet_migrations m
         JOIN subnet_migration_gateways mg ON mg.migration_id=m.id
         JOIN gateways g ON g.id=mg.gateway_id
         WHERE g.agent_id=? AND m.status IN ('preparing','armed','cancelled','failed')
         ORDER BY m.created_at,mg.gateway_id",
    )
    .bind(agent_id.to_string())
    .fetch_all(pool)
    .await
    .map_err(database_status)?;

    for row in rows {
        let migration_id: Uuid = row
            .try_get::<String, _>("id")
            .map_err(database_status)?
            .parse()
            .map_err(|_| Status::internal("stored migration ID is invalid"))?;
        let gateway_id: Uuid = row
            .try_get::<String, _>("gateway_id")
            .map_err(database_status)?
            .parse()
            .map_err(|_| Status::internal("stored gateway ID is invalid"))?;
        let status: String = row.try_get("status").map_err(database_status)?;
        let key = (migration_id, gateway_id);
        let previous = sent.get(&key).map(String::as_str);
        if matches!(status.as_str(), "cancelled" | "failed") {
            if matches!(previous, Some("preparing") | Some("armed")) {
                sender
                    .send(Ok(proto::ControllerMessage {
                        payload: Some(proto::controller_message::Payload::CancelMigration(
                            proto::CancelMigration {
                                migration_id: migration_id.to_string(),
                                reason: status.clone(),
                                gateway_id: gateway_id.to_string(),
                            },
                        )),
                    }))
                    .await
                    .map_err(|_| Status::cancelled("agent disconnected"))?;
                sent.insert(key, status);
            }
            continue;
        }
        if previous == Some(status.as_str()) {
            continue;
        }

        let effective_unix_seconds = chrono::DateTime::parse_from_rfc3339(
            &row.try_get::<String, _>("effective_at").map_err(database_status)?,
        )
        .map_err(|_| Status::internal("stored migration time is invalid"))?
        .timestamp();
        let plan: migration::MigrationPlan = serde_json::from_str(
            &row.try_get::<String, _>("plan_json").map_err(database_status)?,
        )
        .map_err(|_| Status::internal("stored migration plan is invalid"))?;
        let future = plan
            .gateways
            .get(&gateway_id)
            .ok_or_else(|| Status::internal("migration gateway state is missing"))?;

        // A newly connected agent receives prepare immediately before arm so an
        // armed migration survives agent restarts and connection loss.
        if previous.is_none() {
            let future_state = snapshot_with_credentials(pool, secrets, &future.state).await?;
            sender
                .send(Ok(proto::ControllerMessage {
                    payload: Some(proto::controller_message::Payload::PrepareMigration(
                        proto::PrepareMigration {
                            migration_id: migration_id.to_string(),
                            effective_unix_seconds,
                            future_state: Some(future_state),
                        },
                    )),
                }))
                .await
                .map_err(|_| Status::cancelled("agent disconnected"))?;
        }
        if status == "armed" {
            sender
                .send(Ok(proto::ControllerMessage {
                    payload: Some(proto::controller_message::Payload::ArmMigration(
                        proto::ArmMigration {
                            migration_id: migration_id.to_string(),
                            effective_unix_seconds,
                            gateway_id: gateway_id.to_string(),
                        },
                    )),
                }))
                .await
                .map_err(|_| Status::cancelled("agent disconnected"))?;
            sent_revisions.insert(gateway_id, future.state.revision);
        }
        sent.insert(key, status);
    }
    Ok(())
}

async fn send_new_states(
    pool: &SqlitePool,
    secrets: &SecretBox,
    agent_id: Uuid,
    sender: &mpsc::Sender<Result<proto::ControllerMessage, Status>>,
    sent_revisions: &mut HashMap<Uuid, u64>,
) -> Result<(), Status> {
    let states = desired::latest_states_for_agent(pool, agent_id)
        .await
        .map_err(internal_status)?;
    for state in states {
        let sent = sent_revisions.get(&state.gateway_id).copied().unwrap_or(0);
        if state.revision > sent {
            let gateway_id = state.gateway_id;
            let revision = state.revision;
            let snapshot = snapshot_with_credentials(pool, secrets, &state).await?;
            sender
                .send(Ok(proto::ControllerMessage {
                    payload: Some(proto::controller_message::Payload::Desired(
                        snapshot,
                    )),
                }))
                .await
                .map_err(|_| Status::cancelled("agent disconnected"))?;
            sent_revisions.insert(gateway_id, revision);
        }
    }
    Ok(())
}

async fn snapshot_with_credentials(
    pool: &SqlitePool,
    secrets: &SecretBox,
    state: &wiremesh_domain::DesiredGatewayState,
) -> Result<proto::DesiredSnapshot, Status> {
    let mut snapshot = desired_to_proto(state);
    snapshot.credential_envelope = router_target::payload_for_gateway(
        pool,
        secrets,
        state.gateway_id,
    )
    .await
    .map_err(internal_status)?
    .unwrap_or_default();
    Ok(snapshot)
}

async fn handle_message(
    pool: &SqlitePool,
    agent_id: Uuid,
    message: proto::AgentMessage,
) -> Result<(), Status> {
    touch_agent(pool, agent_id).await?;
    match message.payload {
        Some(proto::agent_message::Payload::Heartbeat(_)) => Ok(()),
        Some(proto::agent_message::Payload::Facts(facts)) => {
            record_facts(pool, agent_id, facts).await
        }
        Some(proto::agent_message::Payload::Prepared(prepared)) => {
            verify_gateway_assignment(pool, agent_id, &prepared.gateway_id).await?;
            let migration_id = prepared
                .migration_id
                .parse()
                .map_err(|_| Status::invalid_argument("invalid migration ID"))?;
            let gateway_id = prepared
                .gateway_id
                .parse()
                .map_err(|_| Status::invalid_argument("invalid gateway ID"))?;
            migration::record_prepared(
                pool,
                migration_id,
                gateway_id,
                prepared.revision,
                &prepared.state_hash,
            )
            .await
            .map_err(internal_status)?;
            sqlx::query(
                "INSERT INTO gateway_apply_events(id,gateway_id,revision,outcome,state_hash,created_at) VALUES(?,?,?,?,?,?)",
            )
            .bind(Uuid::now_v7().to_string())
            .bind(&prepared.gateway_id)
            .bind(prepared.revision as i64)
            .bind("prepared")
            .bind(&prepared.state_hash)
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(pool)
            .await
            .map_err(database_status)?;
            sqlx::query(
                "INSERT INTO audit_events(id,occurred_at,actor_kind,action,object_kind,object_id,outcome,details_json)
                 VALUES(?,?,?,?,?,?,?,?)",
            )
            .bind(Uuid::now_v7().to_string())
            .bind(chrono::Utc::now().to_rfc3339())
            .bind("agent")
            .bind("gateway.migration.prepared")
            .bind("gateway")
            .bind(&prepared.gateway_id)
            .bind("success")
            .bind(
                serde_json::json!({
                    "migration_id": migration_id,
                    "revision": prepared.revision,
                    "state_hash": prepared.state_hash,
                })
                .to_string(),
            )
            .execute(pool)
            .await
            .map_err(database_status)?;
            Ok(())
        }
        Some(proto::agent_message::Payload::Applied(applied)) => {
            verify_gateway_assignment(pool, agent_id, &applied.gateway_id).await?;
            let gateway_id = applied
                .gateway_id
                .parse()
                .map_err(|_| Status::invalid_argument("invalid gateway ID"))?;
            desired::record_applied(
                pool,
                gateway_id,
                applied.revision,
                &applied.actual_state_hash,
            )
            .await
            .map_err(internal_status)
        }
        Some(proto::agent_message::Payload::Error(error)) => {
            verify_gateway_assignment(pool, agent_id, &error.gateway_id).await?;
            let gateway_id = error
                .gateway_id
                .parse()
                .map_err(|_| Status::invalid_argument("invalid gateway ID"))?;
            desired::record_error(pool, gateway_id, error.revision, &error.code, &error.message)
                .await
                .map_err(internal_status)
        }
        Some(proto::agent_message::Payload::Hello(_)) => {
            Err(Status::invalid_argument("hello may only be sent once"))
        }
        None => Err(Status::invalid_argument("empty agent message")),
    }
}

async fn authenticate_agent(pool: &SqlitePool, agent_id: Uuid, secret: &str) -> Result<(), Status> {
    let row = sqlx::query("SELECT current_secret_hash,next_secret_hash FROM agents WHERE id=?")
        .bind(agent_id.to_string())
        .fetch_optional(pool)
        .await
        .map_err(database_status)?
        .ok_or_else(|| Status::unauthenticated("agent credentials are invalid"))?;
    let candidate = Sha256::digest(secret.as_bytes());
    let current: Vec<u8> = row.try_get("current_secret_hash").map_err(database_status)?;
    let next: Option<Vec<u8>> = row.try_get("next_secret_hash").map_err(database_status)?;
    let current_matches: bool = candidate.as_slice().ct_eq(current.as_slice()).into();
    let next_matches: bool = next
        .as_deref()
        .is_some_and(|value| bool::from(candidate.as_slice().ct_eq(value)));
    if current_matches || next_matches {
        Ok(())
    } else {
        Err(Status::unauthenticated("agent credentials are invalid"))
    }
}

async fn register_hello(
    pool: &SqlitePool,
    agent_id: Uuid,
    hello: &proto::AgentHello,
) -> Result<(), Status> {
    let capabilities = serde_json::to_string(&hello.capabilities)
        .map_err(|_| Status::internal("encode agent capabilities"))?;
    let timestamp = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE agents SET protocol_major=?,protocol_minor=?,version=?,capabilities_json=?,boot_id=?,last_seen_at=?,updated_at=? WHERE id=?",
    )
    .bind(i64::from(hello.protocol_major))
    .bind(i64::from(hello.protocol_minor.min(PROTOCOL_MINOR)))
    .bind(&hello.agent_version)
    .bind(capabilities)
    .bind(&hello.boot_id)
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(agent_id.to_string())
    .execute(pool)
    .await
    .map_err(database_status)?;
    Ok(())
}

async fn touch_agent(pool: &SqlitePool, agent_id: Uuid) -> Result<(), Status> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    sqlx::query("UPDATE agents SET last_seen_at=?,updated_at=? WHERE id=?")
        .bind(&timestamp)
        .bind(&timestamp)
        .bind(agent_id.to_string())
        .execute(pool)
        .await
        .map_err(database_status)?;
    Ok(())
}

async fn record_facts(
    pool: &SqlitePool,
    agent_id: Uuid,
    facts: proto::GatewayFacts,
) -> Result<(), Status> {
    verify_gateway_assignment(pool, agent_id, &facts.gateway_id).await?;
    wiremesh_domain::validate_wireguard_public_key(&facts.public_key)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    let gateway_id: Uuid = facts
        .gateway_id
        .parse()
        .map_err(|_| Status::invalid_argument("invalid gateway ID"))?;
    let listen_port = u16::try_from(facts.listen_port)
        .map_err(|_| Status::invalid_argument("invalid listen port"))?;
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await.map_err(database_status)?;
    let old = sqlx::query("SELECT public_key,listen_port FROM gateways WHERE id=?")
        .bind(gateway_id.to_string())
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_status)?;
    let old_key: Option<String> = old.try_get("public_key").map_err(database_status)?;
    let old_listen_port: Option<i64> = old.try_get("listen_port").map_err(database_status)?;
    if old_key.as_deref() != Some(facts.public_key.as_str()) {
        let result = sqlx::query(
            "INSERT INTO key_registry(id,public_key,owner_kind,owner_id,activated_at) VALUES(?,?,?,?,?)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(&facts.public_key)
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
                return Err(Status::already_exists("gateway public key is already active"));
            }
            return Err(database_status(error));
        }
        sqlx::query(
            "UPDATE key_registry SET retired_at=? WHERE owner_kind='gateway' AND owner_id=? AND public_key != ? AND retired_at IS NULL",
        )
        .bind(&timestamp)
        .bind(gateway_id.to_string())
        .bind(&facts.public_key)
        .execute(&mut *transaction)
        .await
        .map_err(database_status)?;
    }
    sqlx::query(
        "UPDATE gateways SET public_key=?,listen_port=?,actual_state_hash=?,status='ready',last_error=NULL,last_seen_at=?,updated_at=? WHERE id=?",
    )
    .bind(&facts.public_key)
    .bind(i64::from(listen_port))
    .bind(&facts.actual_state_hash)
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(gateway_id.to_string())
    .execute(&mut *transaction)
    .await
    .map_err(database_status)?;
    if old_key.as_deref() != Some(facts.public_key.as_str())
        || old_listen_port != Some(i64::from(listen_port))
    {
        service::refresh_all_client_configs(&mut transaction)
            .await
            .map_err(internal_status)?;
    }
    transaction.commit().await.map_err(database_status)?;
    Ok(())
}

async fn verify_gateway_assignment(
    pool: &SqlitePool,
    agent_id: Uuid,
    gateway_id: &str,
) -> Result<(), Status> {
    let valid: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateways WHERE id=? AND agent_id=?",
    )
    .bind(gateway_id)
    .bind(agent_id.to_string())
    .fetch_one(pool)
    .await
    .map_err(database_status)?;
    if valid == 1 {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "gateway is not assigned to this agent",
        ))
    }
}

fn bearer_secret(metadata: &tonic::metadata::MetadataMap) -> Result<&str, Status> {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Status::unauthenticated("agent bearer secret is required"))
}

fn database_status(error: sqlx::Error) -> Status {
    tracing::error!(%error, "agent database operation failed");
    Status::internal("controller database operation failed")
}

fn internal_status(error: ApiError) -> Status {
    tracing::error!(%error, "agent controller operation failed");
    Status::internal("controller operation failed")
}
