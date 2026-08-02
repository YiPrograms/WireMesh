//! Linux WireGuard, route, nftables, and conntrack backend.

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    fs,
    io::AsyncWriteExt,
    process::Command,
    sync::Mutex,
};
use uuid::Uuid;
use wiremesh_agent_core::{ApplyOutcome, DriverError, GatewayDriver, ObservedGateway};
use wiremesh_domain::{AclAction, AclRule, DesiredGatewayState, IpProtocol};

pub const BACKEND_NAME: &str = "linux-nftables";

#[derive(Debug)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[async_trait]
pub trait CommandRunner: Send + Sync + 'static {
    async fn run(
        &self,
        program: &str,
        arguments: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandResult, DriverError>;
}

pub struct SystemCommandRunner;

#[async_trait]
impl CommandRunner for SystemCommandRunner {
    async fn run(
        &self,
        program: &str,
        arguments: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandResult, DriverError> {
        let mut command = Command::new(program);
        command
            .args(arguments)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| DriverError::Unavailable(format!("start {program}: {error}")))?;
        if let Some(input) = stdin
            && let Some(mut pipe) = child.stdin.take()
        {
            pipe.write_all(input)
                .await
                .map_err(|error| DriverError::Apply(format!("write to {program}: {error}")))?;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|error| DriverError::Unavailable(format!("wait for {program}: {error}")))?;
        Ok(CommandResult {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

pub struct LinuxDriver<R = SystemCommandRunner> {
    runner: Arc<R>,
    state_directory: PathBuf,
    locks: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
}

impl LinuxDriver<SystemCommandRunner> {
    pub fn system(state_directory: PathBuf) -> Self {
        Self::new(Arc::new(SystemCommandRunner), state_directory)
    }
}

impl<R> LinuxDriver<R> {
    pub fn new(runner: Arc<R>, state_directory: PathBuf) -> Self {
        Self {
            runner,
            state_directory,
            locks: Mutex::new(HashMap::new()),
        }
    }

    async fn gateway_lock(&self, gateway_id: Uuid) -> Arc<Mutex<()>> {
        self.locks
            .lock()
            .await
            .entry(gateway_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AppliedMetadata {
    gateway_id: Uuid,
    interface_name: String,
    listen_port: u16,
}

#[async_trait]
impl<R: CommandRunner> GatewayDriver for LinuxDriver<R> {
    async fn observe(&self, gateway_id: Uuid) -> Result<ObservedGateway, DriverError> {
        let metadata = self.read_metadata(gateway_id).await?;
        let public_key = self
            .checked(
                "wg",
                &["show".into(), metadata.interface_name.clone(), "public-key".into()],
                None,
            )
            .await?;
        let version = self.checked("wg", &["--version".into()], None).await?;
        let actual_state_hash = self
            .live_state_hash(gateway_id, &metadata.interface_name)
            .await?;
        Ok(ObservedGateway {
            gateway_id,
            public_key: String::from_utf8_lossy(&public_key.stdout).trim().into(),
            listen_port: metadata.listen_port,
            actual_state_hash,
            backend_version: String::from_utf8_lossy(&version.stdout).trim().into(),
        })
    }

    async fn validate(&self, desired: &DesiredGatewayState) -> Result<(), DriverError> {
        validate_state(desired)
    }

    async fn apply(&self, desired: &DesiredGatewayState) -> Result<ApplyOutcome, DriverError> {
        validate_state(desired)?;
        let lock = self.gateway_lock(desired.gateway_id).await;
        let _guard = lock.lock().await;
        fs::create_dir_all(&self.state_directory)
            .await
            .map_err(|error| DriverError::Apply(format!("create state directory: {error}")))?;
        self.checked(
            "sysctl",
            &["-q".into(), "-w".into(), "net.ipv4.ip_forward=1".into()],
            None,
        )
        .await?;
        self.ensure_interface(&desired.interface_name).await?;
        let private_key = self.ensure_private_key(desired.gateway_id).await?;
        self.checked(
            "wg",
            &[
                "set".into(),
                desired.interface_name.clone(),
                "private-key".into(),
                private_key.to_string_lossy().into_owned(),
                "listen-port".into(),
                desired.listen_port.to_string(),
            ],
            None,
        )
        .await?;
        let wireguard = render_wireguard(desired);
        self.checked(
            "wg",
            &["syncconf".into(), desired.interface_name.clone(), "/dev/stdin".into()],
            Some(wireguard.as_bytes()),
        )
        .await?;
        if let Some(mtu) = desired.mtu {
            self.checked(
                "ip",
                &[
                    "link".into(),
                    "set".into(),
                    "dev".into(),
                    desired.interface_name.clone(),
                    "mtu".into(),
                    mtu.to_string(),
                ],
                None,
            )
            .await?;
        }
        self.checked(
            "ip",
            &[
                "link".into(),
                "set".into(),
                "dev".into(),
                desired.interface_name.clone(),
                "up".into(),
            ],
            None,
        )
        .await?;
        self.reconcile_routes(desired).await?;
        let nftables = render_nftables(desired)?;
        self.checked("nft", &["-f".into(), "-".into()], Some(nftables.as_bytes()))
            .await?;
        let actual_state_hash = self
            .live_state_hash(desired.gateway_id, &desired.interface_name)
            .await?;
        self.write_metadata(AppliedMetadata {
            gateway_id: desired.gateway_id,
            interface_name: desired.interface_name.clone(),
            listen_port: desired.listen_port,
        })
        .await?;
        Ok(ApplyOutcome {
            revision: desired.revision,
            actual_state_hash,
        })
    }

    async fn flush_connections(&self, sources: &[std::net::Ipv4Addr]) -> Result<(), DriverError> {
        for source in sources {
            let result = self
                .runner
                .run(
                    "conntrack",
                    &["-D".into(), "-s".into(), source.to_string()],
                    None,
                )
                .await?;
            // conntrack exits 1 when no matching flow exists; that is already
            // the desired postcondition. Other errors are surfaced.
            if !result.success {
                let stderr = String::from_utf8_lossy(&result.stderr);
                if !stderr.contains("0 flow entries") && !stderr.contains("0 flow") {
                    return Err(command_failed("conntrack", &result));
                }
            }
        }
        Ok(())
    }
}

impl<R: CommandRunner> LinuxDriver<R> {
    async fn live_state_hash(
        &self,
        gateway_id: Uuid,
        interface: &str,
    ) -> Result<String, DriverError> {
        let wireguard = self
            .checked(
                "wg",
                &["show".into(), interface.into(), "dump".into()],
                None,
            )
            .await?;
        let routes = self
            .checked(
                "ip",
                &[
                    "-4".into(),
                    "route".into(),
                    "show".into(),
                    "dev".into(),
                    interface.into(),
                ],
                None,
            )
            .await?;
        let nftables = self
            .checked(
                "nft",
                &[
                    "-j".into(),
                    "-s".into(),
                    "list".into(),
                    "table".into(),
                    "inet".into(),
                    nft_table_name(gateway_id),
                ],
                None,
            )
            .await?;
        let mut normalized = Vec::new();
        normalized.extend_from_slice(normalize_wg_dump(&wireguard.stdout).as_bytes());
        normalized.push(b'\n');
        normalized.extend_from_slice(normalize_lines(&routes.stdout).as_bytes());
        normalized.push(b'\n');
        normalized.extend_from_slice(normalize_nft_json(&nftables.stdout)?.as_bytes());
        Ok(format!("{:x}", Sha256::digest(normalized)))
    }

    async fn ensure_interface(&self, interface: &str) -> Result<(), DriverError> {
        let exists = self
            .runner
            .run(
                "ip",
                &["link".into(), "show".into(), "dev".into(), interface.into()],
                None,
            )
            .await?;
        if !exists.success {
            self.checked(
                "ip",
                &[
                    "link".into(),
                    "add".into(),
                    "dev".into(),
                    interface.into(),
                    "type".into(),
                    "wireguard".into(),
                ],
                None,
            )
            .await?;
        }
        Ok(())
    }

    async fn ensure_private_key(&self, gateway_id: Uuid) -> Result<PathBuf, DriverError> {
        let path = self.state_directory.join(format!("{gateway_id}.key"));
        if fs::try_exists(&path)
            .await
            .map_err(|error| DriverError::Apply(format!("inspect private key: {error}")))?
        {
            return Ok(path);
        }
        let generated = self.checked("wg", &["genkey".into()], None).await?;
        let key = String::from_utf8(generated.stdout)
            .map_err(|_| DriverError::Apply("wg generated a non-UTF-8 key".into()))?;
        wiremesh_domain::validate_wireguard_public_key(key.trim())
            .map_err(|error| DriverError::Apply(format!("wg generated an invalid key: {error}")))?;
        let temporary = path.with_extension("key.tmp");
        fs::write(&temporary, format!("{}\n", key.trim()))
            .await
            .map_err(|error| DriverError::Apply(format!("persist private key: {error}")))?;
        set_private_permissions(&temporary)?;
        fs::rename(&temporary, &path)
            .await
            .map_err(|error| DriverError::Apply(format!("activate private key: {error}")))?;
        Ok(path)
    }

    async fn reconcile_routes(&self, desired: &DesiredGatewayState) -> Result<(), DriverError> {
        let output = self
            .checked(
                "ip",
                &[
                    "-4".into(),
                    "route".into(),
                    "show".into(),
                    "dev".into(),
                    desired.interface_name.clone(),
                ],
                None,
            )
            .await?;
        let wanted: BTreeSet<String> = desired
            .peers
            .iter()
            .map(|peer| format!("{}/32", peer.allowed_address))
            .collect();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let Some(cidr) = line.split_whitespace().next() else {
                continue;
            };
            if cidr.ends_with("/32") && !wanted.contains(cidr) {
                self.checked(
                    "ip",
                    &[
                        "-4".into(),
                        "route".into(),
                        "delete".into(),
                        cidr.into(),
                        "dev".into(),
                        desired.interface_name.clone(),
                    ],
                    None,
                )
                .await?;
            }
        }
        for cidr in wanted {
            self.checked(
                "ip",
                &[
                    "-4".into(),
                    "route".into(),
                    "replace".into(),
                    cidr,
                    "dev".into(),
                    desired.interface_name.clone(),
                ],
                None,
            )
            .await?;
        }
        Ok(())
    }

    async fn checked(
        &self,
        program: &str,
        arguments: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandResult, DriverError> {
        let result = self.runner.run(program, arguments, stdin).await?;
        if result.success {
            Ok(result)
        } else {
            Err(command_failed(program, &result))
        }
    }

    async fn read_metadata(&self, gateway_id: Uuid) -> Result<AppliedMetadata, DriverError> {
        let bytes = fs::read(self.metadata_path(gateway_id))
            .await
            .map_err(|error| DriverError::Unavailable(format!("read gateway metadata: {error}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| DriverError::Apply(format!("decode gateway metadata: {error}")))
    }

    async fn write_metadata(&self, metadata: AppliedMetadata) -> Result<(), DriverError> {
        let path = self.metadata_path(metadata.gateway_id);
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(&metadata)
            .map_err(|error| DriverError::Apply(format!("encode gateway metadata: {error}")))?;
        fs::write(&temporary, bytes)
            .await
            .map_err(|error| DriverError::Apply(format!("write gateway metadata: {error}")))?;
        fs::rename(temporary, path)
            .await
            .map_err(|error| DriverError::Apply(format!("activate gateway metadata: {error}")))
    }

    fn metadata_path(&self, gateway_id: Uuid) -> PathBuf {
        self.state_directory.join(format!("{gateway_id}.metadata.json"))
    }
}

pub fn render_wireguard(desired: &DesiredGatewayState) -> String {
    let mut rendered = String::from("[Interface]\n");
    for peer in &desired.peers {
        rendered.push_str("\n[Peer]\nPublicKey = ");
        rendered.push_str(&peer.public_key);
        rendered.push_str("\nAllowedIPs = ");
        rendered.push_str(&format!("{}/32\n", peer.allowed_address));
    }
    rendered
}

pub fn render_nftables(desired: &DesiredGatewayState) -> Result<String, DriverError> {
    validate_state(desired)?;
    let table = nft_table_name(desired.gateway_id);
    let sources = desired
        .peers
        .iter()
        .map(|peer| peer.allowed_address.to_string())
        .collect::<Vec<_>>();
    let destinations = desired.routes.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut rendered = format!(
        "destroy table inet {table}\nadd table inet {table}\nadd chain inet {table} forward {{ type filter hook forward priority filter; policy accept; }}\nadd rule inet {table} forward iifname != \"{}\" return\nadd rule inet {table} forward ct state established,related accept\n",
        desired.interface_name
    );
    if sources.is_empty() {
        rendered.push_str(&format!("add rule inet {table} forward drop\n"));
        return Ok(rendered);
    }
    rendered.push_str(&format!(
        "add rule inet {table} forward ip saddr != {{ {} }} drop\n",
        sources.join(", ")
    ));
    rendered.push_str(&format!(
        "add rule inet {table} forward ip daddr != {{ {} }} drop\n",
        destinations.join(", ")
    ));
    let mut rules: Vec<&AclRule> = desired.acl_rules.iter().filter(|rule| rule.enabled).collect();
    rules.sort_by_key(|rule| (rule.position, rule.id));
    for rule in rules {
        let matching_sources = desired
            .peers
            .iter()
            .filter(|peer| rule.subjects.matches(peer.user_id, &peer.group_ids))
            .map(|peer| peer.allowed_address.to_string())
            .collect::<Vec<_>>();
        if matching_sources.is_empty() {
            continue;
        }
        rendered.push_str(&format!(
            "add rule inet {table} forward ip saddr {{ {} }} ip daddr {}",
            matching_sources.join(", "),
            rule.destination
        ));
        match rule.protocol {
            IpProtocol::Any => {}
            IpProtocol::Tcp => rendered.push_str(" meta l4proto tcp"),
            IpProtocol::Udp => rendered.push_str(" meta l4proto udp"),
            IpProtocol::Icmp => rendered.push_str(" meta l4proto icmp"),
        }
        if let Some(ports) = &rule.destination_ports {
            let protocol = match rule.protocol {
                IpProtocol::Tcp => "tcp",
                IpProtocol::Udp => "udp",
                _ => {
                    return Err(DriverError::Invalid(
                        "ports are valid only with TCP or UDP".into(),
                    ));
                }
            };
            if ports.start == ports.end {
                rendered.push_str(&format!(" {protocol} dport {}", ports.start));
            } else {
                rendered.push_str(&format!(
                    " {protocol} dport {}-{}",
                    ports.start, ports.end
                ));
            }
        }
        rendered.push(' ');
        rendered.push_str(action_name(rule.action));
        rendered.push_str(&format!(" comment \"wiremesh rule {}\"\n", rule.id));
    }
    rendered.push_str(&format!(
        "add rule inet {table} forward {} comment \"wiremesh site default\"\n",
        action_name(desired.acl_default)
    ));
    Ok(rendered)
}

fn validate_state(desired: &DesiredGatewayState) -> Result<(), DriverError> {
    if desired.interface_name.is_empty()
        || desired.interface_name.len() > 15
        || !desired.interface_name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(DriverError::Invalid("invalid Linux interface name".into()));
    }
    if desired.listen_port == 0 {
        return Err(DriverError::Invalid("listen port cannot be zero".into()));
    }
    if desired.routes.is_empty() {
        return Err(DriverError::Invalid("site must have protected routes".into()));
    }
    let mut addresses = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for peer in &desired.peers {
        wiremesh_domain::validate_wireguard_public_key(&peer.public_key)
            .map_err(|error| DriverError::Invalid(error.to_string()))?;
        if !addresses.insert(peer.allowed_address) || !keys.insert(peer.public_key.as_str()) {
            return Err(DriverError::Invalid(
                "duplicate peer address or public key".into(),
            ));
        }
    }
    for rule in &desired.acl_rules {
        if rule.destination_ports.is_some()
            && !matches!(rule.protocol, IpProtocol::Tcp | IpProtocol::Udp)
        {
            return Err(DriverError::Invalid(
                "ACL ports require TCP or UDP".into(),
            ));
        }
    }
    Ok(())
}

fn action_name(action: AclAction) -> &'static str {
    match action {
        AclAction::Allow => "accept",
        AclAction::Deny => "drop",
    }
}

fn nft_table_name(gateway_id: Uuid) -> String {
    let compact = gateway_id.simple().to_string();
    format!("wm_{}", &compact[..12])
}

fn normalize_wg_dump(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.lines();
    let interface = lines
        .next()
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            format!(
                "interface:{}:{}:{}",
                fields.get(1).copied().unwrap_or_default(),
                fields.get(2).copied().unwrap_or_default(),
                fields.get(3).copied().unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let mut peers = lines
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            format!(
                "peer:{}:{}:{}",
                fields.first().copied().unwrap_or_default(),
                fields.get(3).copied().unwrap_or_default(),
                fields.get(7).copied().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    peers.sort();
    std::iter::once(interface)
        .chain(peers)
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_lines(bytes: &[u8]) -> String {
    let mut lines = String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines.sort();
    lines.join("\n")
}

fn normalize_nft_json(bytes: &[u8]) -> Result<String, DriverError> {
    fn scrub(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                for key in ["handle", "packets", "bytes", "metainfo"] {
                    object.remove(key);
                }
                for value in object.values_mut() {
                    scrub(value);
                }
            }
            serde_json::Value::Array(values) => values.iter_mut().for_each(scrub),
            _ => {}
        }
    }
    let mut value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| DriverError::Apply(format!("decode nftables state: {error}")))?;
    scrub(&mut value);
    serde_json::to_string(&value)
        .map_err(|error| DriverError::Apply(format!("encode nftables state: {error}")))
}

fn command_failed(program: &str, result: &CommandResult) -> DriverError {
    let stderr = String::from_utf8_lossy(&result.stderr);
    DriverError::Apply(format!("{program} failed: {}", stderr.trim()))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), DriverError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| DriverError::Apply(format!("secure private key: {error}")))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), DriverError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::Ipv4Addr};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use wiremesh_domain::{AclSubjects, DesiredPeer, PortRange};

    use super::*;

    fn desired() -> DesiredGatewayState {
        let group = Uuid::new_v4();
        DesiredGatewayState {
            gateway_id: Uuid::nil(),
            revision: 4,
            interface_name: "wm0".into(),
            listen_port: 51_820,
            mtu: Some(1_420),
            compatibility_address: None,
            routes: vec!["10.40.0.0/16".parse().unwrap()],
            peers: vec![DesiredPeer {
                device_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                public_key: STANDARD.encode([7_u8; 32]),
                allowed_address: Ipv4Addr::new(10, 20, 0, 2),
                group_ids: BTreeSet::from([group]),
            }],
            acl_default: AclAction::Deny,
            acl_rules: vec![AclRule {
                id: Uuid::nil(),
                position: 10,
                action: AclAction::Allow,
                destination: "10.40.1.0/24".parse().unwrap(),
                protocol: IpProtocol::Tcp,
                destination_ports: Some(PortRange { start: 22, end: 22 }),
                subjects: AclSubjects {
                    users: BTreeSet::new(),
                    groups: BTreeSet::from([group]),
                },
                enabled: true,
            }],
            terminate_sources: vec![],
        }
    }

    #[test]
    fn wireguard_configuration_contains_only_public_peer_material() {
        let rendered = render_wireguard(&desired());
        assert!(rendered.contains("AllowedIPs = 10.20.0.2/32"));
        assert!(!rendered.contains("PrivateKey"));
    }

    #[test]
    fn nftables_policy_is_ordered_stateful_and_anti_spoofing() {
        let rendered = render_nftables(&desired()).unwrap();
        let established = rendered.find("established,related").unwrap();
        let acl = rendered.find("tcp dport 22 accept").unwrap();
        let default = rendered.find("wiremesh site default").unwrap();
        assert!(established < acl && acl < default);
        assert!(rendered.contains("ip saddr != { 10.20.0.2 } drop"));
        assert!(rendered.contains("ip daddr != { 10.40.0.0/16 } drop"));
        assert!(rendered.starts_with("destroy table inet wm_"));
    }
}
