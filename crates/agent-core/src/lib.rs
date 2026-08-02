use std::{collections::HashMap, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{fs, sync::Mutex};
use uuid::Uuid;
use wiremesh_domain::DesiredGatewayState;

pub mod protocol;
pub mod runtime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGateway {
    pub gateway_id: Uuid,
    pub public_key: String,
    pub listen_port: u16,
    pub actual_state_hash: String,
    pub backend_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub revision: u64,
    pub actual_state_hash: String,
}

/// Backend connection material delivered inside the authenticated TLS stream.
/// It is deliberately separate from `DesiredGatewayState` so reconciliation
/// caches never persist credentials.
#[derive(Clone, Serialize, Deserialize)]
pub struct GatewayCredential {
    pub backend: String,
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub ca_certificate_pem: String,
}

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("invalid desired state: {0}")]
    Invalid(String),
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("backend apply failed: {0}")]
    Apply(String),
}

impl DriverError {
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

#[async_trait]
pub trait GatewayDriver: Send + Sync + 'static {
    async fn configure_gateway(
        &self,
        _gateway_id: Uuid,
        _credential: GatewayCredential,
    ) -> Result<(), DriverError> {
        Ok(())
    }
    async fn observe(&self, gateway_id: Uuid) -> Result<ObservedGateway, DriverError>;
    async fn validate(&self, desired: &DesiredGatewayState) -> Result<(), DriverError>;
    async fn apply(&self, desired: &DesiredGatewayState) -> Result<ApplyOutcome, DriverError>;
    async fn flush_connections(&self, sources: &[std::net::Ipv4Addr]) -> Result<(), DriverError>;
}

#[derive(Debug, Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Driver(#[from] DriverError),
    #[error("refusing stale revision {incoming}; current revision is {current}")]
    StaleRevision { incoming: u64, current: u64 },
    #[error("failed to persist desired-state cache: {0}")]
    Cache(#[from] std::io::Error),
    #[error("failed to encode desired-state cache: {0}")]
    Encode(#[from] serde_json::Error),
}

pub struct Reconciler<D> {
    driver: Arc<D>,
    cache_directory: PathBuf,
    current_revisions: Mutex<HashMap<Uuid, u64>>,
    actual_hashes: Mutex<HashMap<Uuid, String>>,
}

impl<D: GatewayDriver> Reconciler<D> {
    pub fn new(driver: Arc<D>, cache_directory: PathBuf) -> Self {
        Self {
            driver,
            cache_directory,
            current_revisions: Mutex::new(HashMap::new()),
            actual_hashes: Mutex::new(HashMap::new()),
        }
    }

    pub async fn validate(&self, desired: &DesiredGatewayState) -> Result<String, ReconcileError> {
        self.driver.validate(desired).await?;
        Ok(state_hash(desired))
    }

    pub async fn observe(&self, gateway_id: Uuid) -> Result<ObservedGateway, ReconcileError> {
        Ok(self.driver.observe(gateway_id).await?)
    }

    pub async fn configure_gateway(
        &self,
        gateway_id: Uuid,
        credential: GatewayCredential,
    ) -> Result<(), ReconcileError> {
        Ok(self.driver.configure_gateway(gateway_id, credential).await?)
    }

    pub async fn current_gateways(&self) -> Vec<(Uuid, u64)> {
        let mut gateways = self
            .current_revisions
            .lock()
            .await
            .iter()
            .map(|(gateway_id, revision)| (*gateway_id, *revision))
            .collect::<Vec<_>>();
        gateways.sort_by_key(|(gateway_id, _)| *gateway_id);
        gateways
    }

    pub async fn apply(
        &self,
        mut desired: DesiredGatewayState,
    ) -> Result<ApplyOutcome, ReconcileError> {
        desired.canonicalize();
        let mut revisions = self.current_revisions.lock().await;
        let current = revisions.get(&desired.gateway_id).copied().unwrap_or(0);
        if desired.revision < current {
            return Err(ReconcileError::StaleRevision {
                incoming: desired.revision,
                current,
            });
        }
        self.driver.validate(&desired).await?;
        let outcome = self.driver.apply(&desired).await?;
        if !desired.terminate_sources.is_empty() {
            self.driver
                .flush_connections(&desired.terminate_sources)
                .await?;
        }
        self.persist(&desired).await?;
        revisions.insert(desired.gateway_id, desired.revision);
        self.actual_hashes
            .lock()
            .await
            .insert(desired.gateway_id, outcome.actual_state_hash.clone());
        Ok(outcome)
    }

    /// Observe cached gateways and reapply the last desired state when the
    /// backend's live fingerprint differs from the post-apply fingerprint.
    pub async fn reconcile_drift(
        &self,
    ) -> Result<Vec<(Uuid, ApplyOutcome)>, ReconcileError> {
        let states = self.restore_all_cached().await?;
        let mut repaired = Vec::new();
        for state in states {
            let expected = self.actual_hashes.lock().await.get(&state.gateway_id).cloned();
            let drifted = match self.driver.observe(state.gateway_id).await {
                Ok(observed) => expected.as_deref() != Some(observed.actual_state_hash.as_str()),
                Err(error) => {
                    tracing::warn!(gateway_id = %state.gateway_id, %error, "gateway observation failed; attempting reconciliation");
                    true
                }
            };
            if drifted {
                let gateway_id = state.gateway_id;
                repaired.push((gateway_id, self.apply(state).await?));
            }
        }
        Ok(repaired)
    }

    pub async fn restore_cached(
        &self,
        gateway_id: Uuid,
    ) -> Result<Option<DesiredGatewayState>, ReconcileError> {
        match fs::read(self.cache_path(gateway_id)).await {
            Ok(bytes) => {
                let state: DesiredGatewayState = serde_json::from_slice(&bytes)?;
                self.current_revisions
                    .lock()
                    .await
                    .insert(state.gateway_id, state.revision);
                Ok(Some(state))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn restore_all_cached(&self) -> Result<Vec<DesiredGatewayState>, ReconcileError> {
        let mut states = Vec::new();
        let mut entries = match fs::read_dir(&self.cache_directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(states),
            Err(error) => return Err(error.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json")
                || path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.starts_with("prepared-"))
            {
                continue;
            }
            let bytes = fs::read(path).await?;
            let state: DesiredGatewayState = serde_json::from_slice(&bytes)?;
            self.current_revisions
                .lock()
                .await
                .insert(state.gateway_id, state.revision);
            states.push(state);
        }
        states.sort_by_key(|state| state.gateway_id);
        Ok(states)
    }

    pub async fn prepare(
        &self,
        migration_id: Uuid,
        mut desired: DesiredGatewayState,
    ) -> Result<String, ReconcileError> {
        desired.canonicalize();
        self.driver.validate(&desired).await?;
        fs::create_dir_all(&self.cache_directory).await?;
        let path = self
            .cache_directory
            .join(format!("prepared-{migration_id}-{}.json", desired.gateway_id));
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec(&desired)?).await?;
        fs::rename(temporary, path).await?;
        Ok(state_hash(&desired))
    }

    pub async fn discard_prepared(
        &self,
        migration_id: Uuid,
        gateway_id: Uuid,
    ) -> Result<(), ReconcileError> {
        let path = self
            .cache_directory
            .join(format!("prepared-{migration_id}-{gateway_id}.json"));
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn persist(&self, desired: &DesiredGatewayState) -> Result<(), ReconcileError> {
        fs::create_dir_all(&self.cache_directory).await?;
        let cache_path = self.cache_path(desired.gateway_id);
        let temporary = cache_path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec(desired)?).await?;
        fs::rename(temporary, cache_path).await?;
        Ok(())
    }

    fn cache_path(&self, gateway_id: Uuid) -> PathBuf {
        self.cache_directory.join(format!("{gateway_id}.json"))
    }
}

pub fn state_hash(desired: &DesiredGatewayState) -> String {
    let mut canonical = desired.clone();
    canonical.canonicalize();
    let bytes = serde_json::to_vec(&canonical).expect("desired state is serializable");
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use wiremesh_domain::AclAction;

    use super::*;

    struct FakeDriver {
        applies: AtomicUsize,
        flushes: AtomicUsize,
    }

    #[async_trait]
    impl GatewayDriver for FakeDriver {
        async fn observe(&self, gateway_id: Uuid) -> Result<ObservedGateway, DriverError> {
            Ok(ObservedGateway {
                gateway_id,
                public_key: String::new(),
                listen_port: 51820,
                actual_state_hash: String::new(),
                backend_version: "fake".into(),
            })
        }

        async fn validate(&self, _desired: &DesiredGatewayState) -> Result<(), DriverError> {
            Ok(())
        }

        async fn apply(&self, desired: &DesiredGatewayState) -> Result<ApplyOutcome, DriverError> {
            self.applies.fetch_add(1, Ordering::SeqCst);
            Ok(ApplyOutcome {
                revision: desired.revision,
                actual_state_hash: state_hash(desired),
            })
        }

        async fn flush_connections(&self, sources: &[Ipv4Addr]) -> Result<(), DriverError> {
            self.flushes.fetch_add(sources.len(), Ordering::SeqCst);
            Ok(())
        }
    }

    fn desired(revision: u64) -> DesiredGatewayState {
        DesiredGatewayState {
            gateway_id: Uuid::new_v4(),
            revision,
            interface_name: "wm0".into(),
            listen_port: 51820,
            mtu: None,
            compatibility_address: None,
            routes: vec![],
            peers: vec![],
            acl_default: AclAction::Allow,
            acl_rules: vec![],
            terminate_sources: vec![Ipv4Addr::new(10, 20, 0, 2)],
        }
    }

    #[tokio::test]
    async fn applies_flushes_and_caches() {
        let directory = tempfile::tempdir().unwrap();
        let driver = Arc::new(FakeDriver {
            applies: AtomicUsize::new(0),
            flushes: AtomicUsize::new(0),
        });
        let reconciler = Reconciler::new(driver.clone(), directory.path().to_path_buf());
        let state = desired(2);
        let gateway_id = state.gateway_id;
        reconciler.apply(state).await.unwrap();
        assert_eq!(driver.applies.load(Ordering::SeqCst), 1);
        assert_eq!(driver.flushes.load(Ordering::SeqCst), 1);
        assert_eq!(
            reconciler
                .restore_all_cached()
                .await
                .unwrap()
                .first()
                .unwrap()
                .revision,
            2
        );
        let mut stale = desired(1);
        stale.gateway_id = gateway_id;
        assert!(matches!(
            reconciler.apply(stale).await,
            Err(ReconcileError::StaleRevision { .. })
        ));
    }
}
