use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use futures::StreamExt;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Request,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};
use uuid::Uuid;
use wiremesh_domain::DesiredGatewayState;
use wiremesh_proto::{PROTOCOL_MAJOR, PROTOCOL_MINOR, v1 as proto};

use crate::{GatewayCredential, GatewayDriver, ReconcileError, Reconciler, protocol::desired_from_proto};

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub controller_url: String,
    pub server_name: String,
    pub ca_certificate: PathBuf,
    pub agent_id: Uuid,
    pub secret: String,
    pub cache_directory: PathBuf,
    pub capabilities: Vec<String>,
    pub heartbeat_interval: Duration,
}

impl AgentConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.controller_url.starts_with("https://") {
            anyhow::bail!("controller URL must use https://");
        }
        if self.server_name.trim().is_empty() {
            anyhow::bail!("TLS server name is required");
        }
        if self.secret.len() < 32 {
            anyhow::bail!("agent secret is invalid");
        }
        Ok(())
    }
}

pub async fn run_forever<D: GatewayDriver>(config: AgentConfig, driver: Arc<D>) -> anyhow::Result<()> {
    config.validate()?;
    let reconciler = Arc::new(Reconciler::new(driver, config.cache_directory.clone()));
    for cached in reconciler.restore_all_cached().await? {
        match reconciler.apply(cached).await {
            Ok(outcome) => tracing::info!(revision = outcome.revision, "restored cached gateway state"),
            Err(error) => tracing::warn!(%error, "could not restore cached gateway state"),
        }
    }

    let mut delay = Duration::from_secs(1);
    loop {
        match connect_once(&config, reconciler.clone()).await {
            Ok(()) => tracing::warn!("controller closed the agent stream"),
            Err(error) => tracing::warn!(%error, "agent connection failed"),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

async fn connect_once<D: GatewayDriver>(
    config: &AgentConfig,
    reconciler: Arc<Reconciler<D>>,
) -> anyhow::Result<()> {
    let channel = tls_channel(config).await?;
    let mut client = proto::agent_control_client::AgentControlClient::new(channel);
    let (outgoing, receiver) = mpsc::channel::<proto::AgentMessage>(32);
    outgoing.send(hello(config)).await?;
    let mut request = Request::new(ReceiverStream::new(receiver));
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {}", config.secret))?,
    );
    let mut incoming = client.synchronize(request).await?.into_inner();
    tracing::info!(controller = %config.controller_url, "agent connected");
    let pending = Arc::new(Mutex::new(HashMap::<(Uuid, Uuid), DesiredGatewayState>::new()));
    let mut heartbeat = tokio::time::interval(config.heartbeat_interval);
    let mut heartbeat_count = 0_u8;
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                heartbeat_count = heartbeat_count.wrapping_add(1);
                outgoing.send(proto::AgentMessage {
                    payload: Some(proto::agent_message::Payload::Heartbeat(proto::Heartbeat {
                        unix_seconds: chrono::Utc::now().timestamp(),
                    })),
                }).await?;
                if heartbeat_count % 3 == 0 {
                    match reconciler.reconcile_drift().await {
                        Ok(repaired) => {
                            for (gateway_id, outcome) in repaired {
                                tracing::warn!(%gateway_id, revision = outcome.revision, "repaired gateway configuration drift");
                                outgoing.send(applied(gateway_id, outcome)).await?;
                            }
                        }
                        Err(error) => tracing::warn!(%error, "gateway drift observation failed"),
                    }
                    for (gateway_id, revision) in reconciler.current_gateways().await {
                        match reconciler_driver_facts(&reconciler, gateway_id).await {
                            Ok(facts) => outgoing.send(facts).await?,
                            Err(error) => {
                                tracing::warn!(%gateway_id, %error, "gateway fact observation failed");
                                outgoing.send(apply_error(&gateway_id.to_string(), revision, &error)).await?;
                            }
                        }
                    }
                }
            }
            message = incoming.next() => {
                let Some(message) = message else { return Ok(()); };
                handle_controller_message(
                    message?,
                    reconciler.clone(),
                    outgoing.clone(),
                    pending.clone(),
                ).await?;
            }
        }
    }
}

async fn handle_controller_message<D: GatewayDriver>(
    message: proto::ControllerMessage,
    reconciler: Arc<Reconciler<D>>,
    outgoing: mpsc::Sender<proto::AgentMessage>,
    pending: Arc<Mutex<HashMap<(Uuid, Uuid), DesiredGatewayState>>>,
) -> anyhow::Result<()> {
    match message.payload {
        Some(proto::controller_message::Payload::Desired(snapshot)) => {
            let gateway_id = snapshot.gateway_id.clone();
            let revision = snapshot.revision;
            if let Err(error) = configure_gateway(&snapshot, reconciler.clone()).await {
                outgoing.send(apply_error(&gateway_id, revision, &error)).await?;
                return Ok(());
            }
            match desired_from_proto(snapshot) {
                Ok(state) => match reconciler.apply(state.clone()).await {
                    Ok(outcome) => {
                        outgoing.send(applied(state.gateway_id, outcome)).await?;
                        if let Ok(facts) = reconciler_driver_facts(&reconciler, state.gateway_id).await {
                            outgoing.send(facts).await?;
                        }
                    }
                    Err(error) => outgoing.send(apply_error(&gateway_id, revision, &error)).await?,
                },
                Err(error) => {
                    outgoing.send(proto::AgentMessage {
                        payload: Some(proto::agent_message::Payload::Error(proto::ApplyError {
                            gateway_id,
                            revision,
                            code: "invalid_snapshot".into(),
                            message: error.to_string(),
                            retryable: false,
                        })),
                    }).await?;
                }
            }
        }
        Some(proto::controller_message::Payload::PrepareMigration(prepare)) => {
            let migration_id: Uuid = prepare.migration_id.parse()?;
            let snapshot = prepare.future_state.ok_or_else(|| anyhow::anyhow!("migration state missing"))?;
            if let Err(error) = configure_gateway(&snapshot, reconciler.clone()).await {
                outgoing
                    .send(apply_error(&snapshot.gateway_id, snapshot.revision, &error))
                    .await?;
                return Ok(());
            }
            let state = desired_from_proto(snapshot)?;
            let hash = reconciler.prepare(migration_id, state.clone()).await?;
            pending
                .lock()
                .await
                .insert((migration_id, state.gateway_id), state.clone());
            outgoing.send(proto::AgentMessage {
                payload: Some(proto::agent_message::Payload::Prepared(proto::RevisionPrepared {
                    migration_id: migration_id.to_string(),
                    gateway_id: state.gateway_id.to_string(),
                    revision: state.revision,
                    state_hash: hash,
                })),
            }).await?;
        }
        Some(proto::controller_message::Payload::ArmMigration(arm)) => {
            let migration_id: Uuid = arm.migration_id.parse()?;
            let gateway_id: Uuid = arm.gateway_id.parse()?;
            let state = pending.lock().await.remove(&(migration_id, gateway_id))
                .ok_or_else(|| anyhow::anyhow!("controller armed an unprepared migration"))?;
            let reconciler = reconciler.clone();
            let outgoing = outgoing.clone();
            tokio::spawn(async move {
                let now = chrono::Utc::now().timestamp();
                if arm.effective_unix_seconds > now {
                    tokio::time::sleep(Duration::from_secs((arm.effective_unix_seconds - now) as u64)).await;
                }
                let gateway_id = state.gateway_id;
                let revision = state.revision;
                let message = match reconciler.apply(state).await {
                    Ok(outcome) => applied(gateway_id, outcome),
                    Err(error) => apply_error(&gateway_id.to_string(), revision, &error),
                };
                if let Err(error) = reconciler.discard_prepared(migration_id, gateway_id).await {
                    tracing::warn!(%migration_id, %gateway_id, %error, "could not remove prepared migration cache");
                }
                let _ = outgoing.send(message).await;
            });
        }
        Some(proto::controller_message::Payload::CancelMigration(cancel)) => {
            if let (Ok(migration_id), Ok(gateway_id)) =
                (cancel.migration_id.parse(), cancel.gateway_id.parse())
            {
                pending.lock().await.remove(&(migration_id, gateway_id));
                reconciler.discard_prepared(migration_id, gateway_id).await?;
            }
        }
        Some(proto::controller_message::Payload::Ping(_)) | None => {}
    }
    Ok(())
}

async fn configure_gateway<D: GatewayDriver>(
    snapshot: &proto::DesiredSnapshot,
    reconciler: Arc<Reconciler<D>>,
) -> Result<(), ReconcileError> {
    if snapshot.credential_envelope.is_empty() {
        return Ok(());
    }
    let gateway_id = snapshot.gateway_id.parse().map_err(|_| {
        ReconcileError::Driver(crate::DriverError::Invalid("invalid gateway ID".into()))
    })?;
    let credential: GatewayCredential = serde_json::from_slice(&snapshot.credential_envelope)
        .map_err(ReconcileError::Encode)?;
    reconciler.configure_gateway(gateway_id, credential).await
}

async fn reconciler_driver_facts<D: GatewayDriver>(
    reconciler: &Reconciler<D>,
    gateway_id: Uuid,
) -> Result<proto::AgentMessage, ReconcileError> {
    let facts = reconciler.observe(gateway_id).await?;
    Ok(proto::AgentMessage {
        payload: Some(proto::agent_message::Payload::Facts(proto::GatewayFacts {
            gateway_id: facts.gateway_id.to_string(),
            public_key: facts.public_key,
            listen_port: u32::from(facts.listen_port),
            actual_state_hash: facts.actual_state_hash,
            backend_version: facts.backend_version,
        })),
    })
}

fn hello(config: &AgentConfig) -> proto::AgentMessage {
    proto::AgentMessage {
        payload: Some(proto::agent_message::Payload::Hello(proto::AgentHello {
            agent_id: config.agent_id.to_string(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            boot_id: boot_id(),
            capabilities: config.capabilities.clone(),
        })),
    }
}

fn applied(gateway_id: Uuid, outcome: crate::ApplyOutcome) -> proto::AgentMessage {
    proto::AgentMessage {
        payload: Some(proto::agent_message::Payload::Applied(proto::RevisionApplied {
            gateway_id: gateway_id.to_string(),
            revision: outcome.revision,
            actual_state_hash: outcome.actual_state_hash,
            applied_unix_seconds: chrono::Utc::now().timestamp(),
        })),
    }
}

fn apply_error(gateway_id: &str, revision: u64, error: &ReconcileError) -> proto::AgentMessage {
    proto::AgentMessage {
        payload: Some(proto::agent_message::Payload::Error(proto::ApplyError {
            gateway_id: gateway_id.into(),
            revision,
            code: match error {
                ReconcileError::StaleRevision { .. } => "stale_revision",
                ReconcileError::Driver(_) => "backend_error",
                ReconcileError::Cache(_) | ReconcileError::Encode(_) => "cache_error",
            }
            .into(),
            message: error.to_string(),
            retryable: matches!(error, ReconcileError::Driver(driver) if driver.retryable()),
        })),
    }
}

async fn tls_channel(config: &AgentConfig) -> anyhow::Result<Channel> {
    let pem = tokio::fs::read(&config.ca_certificate).await?;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(pem))
        .domain_name(config.server_name.clone());
    Ok(Endpoint::from_shared(config.controller_url.clone())?
        .tls_config(tls)?
        .connect()
        .await?)
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| Uuid::new_v4().to_string())
}
