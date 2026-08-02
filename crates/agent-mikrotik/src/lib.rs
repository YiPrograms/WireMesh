//! MikroTik RouterOS HTTPS REST backend.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use url::Url;
use uuid::Uuid;
use wiremesh_agent_core::{
    ApplyOutcome, DriverError, GatewayCredential, GatewayDriver, ObservedGateway,
};
use wiremesh_domain::{AclAction, DesiredGatewayState, IpProtocol};

pub const MINIMUM_ROUTEROS_VERSION: &str = "7.15";

struct RouterTarget {
    base_url: Url,
    username: String,
    password: String,
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterOperation {
    pub resource: String,
    pub body: Value,
}

#[derive(Debug, Clone)]
struct Metadata {
    interface_name: String,
    listen_port: u16,
}

pub struct MikrotikDriver {
    targets: RwLock<HashMap<Uuid, Arc<RouterTarget>>>,
    metadata: Mutex<HashMap<Uuid, Metadata>>,
}

fn build_target(
    gateway_id: Uuid,
    base_url: Url,
    username: String,
    password: String,
    ca_certificate_pem: &[u8],
) -> Result<RouterTarget, DriverError> {
    if base_url.scheme() != "https" {
        return Err(DriverError::Invalid(format!(
            "RouterOS URL for {gateway_id} must use HTTPS"
        )));
    }
    if !base_url.has_host()
        || !matches!(base_url.path(), "" | "/")
        || base_url.query().is_some()
        || base_url.fragment().is_some()
    {
        return Err(DriverError::Invalid(
            "RouterOS base URL must not include /rest, a query, or a fragment".into(),
        ));
    }
    if username.trim().is_empty() || password.is_empty() {
        return Err(DriverError::Invalid(
            "RouterOS username and password are required".into(),
        ));
    }
    let certificate = reqwest::Certificate::from_pem(ca_certificate_pem)
        .map_err(|error| DriverError::Invalid(format!("invalid RouterOS CA certificate: {error}")))?;
    let client = Client::builder()
        .https_only(true)
        .add_root_certificate(certificate)
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| DriverError::Invalid(format!("build RouterOS HTTPS client: {error}")))?;
    Ok(RouterTarget {
        base_url,
        username,
        password,
        client,
    })
}

impl MikrotikDriver {
    pub fn empty() -> Self {
        Self {
            targets: RwLock::new(HashMap::new()),
            metadata: Mutex::new(HashMap::new()),
        }
    }

    async fn target(&self, gateway_id: Uuid) -> Result<Arc<RouterTarget>, DriverError> {
        self.targets.read().await.get(&gateway_id).cloned().ok_or_else(|| {
            DriverError::Invalid(format!("no RouterOS target configured for {gateway_id}"))
        })
    }

    async fn check_version(&self, target: &RouterTarget) -> Result<String, DriverError> {
        let resource = target.get_object(&["system", "resource"]).await?;
        let version = resource
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::Apply("RouterOS did not report its version".into()))?;
        if !supported_version(version) {
            return Err(DriverError::Invalid(format!(
                "RouterOS {version} is unsupported; {MINIMUM_ROUTEROS_VERSION}+ is required"
            )));
        }
        Ok(version.into())
    }

    async fn reconcile(&self, target: &RouterTarget, desired: &DesiredGatewayState) -> Result<(), DriverError> {
        let prefix = managed_prefix(desired.gateway_id);
        let interface_id = ensure_interface(target, desired, &prefix).await?;

        // The selected WireGuard interface is exclusive: remove every existing
        // peer on it, while leaving all peers on other interfaces untouched.
        for peer in target.list(&["interface", "wireguard", "peers"]).await? {
            if peer.get("interface").and_then(Value::as_str) == Some(desired.interface_name.as_str()) {
                if let Some(id) = resource_id(&peer) {
                    target.delete(&["interface", "wireguard", "peers"], id).await?;
                }
            }
        }
        for peer in &desired.peers {
            target.post(&["interface", "wireguard", "peers"], &json!({
                "interface": desired.interface_name,
                "public-key": peer.public_key,
                "allowed-address": format!("{}/32", peer.allowed_address),
                "comment": format!("{prefix}:peer:{}", peer.device_id),
            })).await?;
        }

        remove_managed(target, &["ip", "route"], &prefix).await?;
        for operation in route_operations(desired) {
            target.post_path(&operation.resource, &operation.body).await?;
        }

        remove_managed(target, &["ip", "address"], &prefix).await?;
        if let Some(address) = desired.compatibility_address {
            target.post(&["ip", "address"], &json!({
                "address": format!("{address}/32"),
                "interface": desired.interface_name,
                "comment": format!("{prefix}:compatibility-address"),
            })).await?;
        }

        remove_managed(target, &["ip", "firewall", "filter"], &prefix).await?;
        remove_managed(target, &["ip", "firewall", "address-list"], &prefix).await?;
        for operation in firewall_operations(desired)? {
            target.post_path(&operation.resource, &operation.body).await?;
        }

        // Fetching by ID confirms that the interface still exists after all
        // related reconciliation calls and catches concurrent administrator deletion.
        let _ = target
            .get_object(&["interface", "wireguard", &interface_id])
            .await?;
        Ok(())
    }
}

#[async_trait]
impl GatewayDriver for MikrotikDriver {
    async fn configure_gateway(
        &self,
        gateway_id: Uuid,
        credential: GatewayCredential,
    ) -> Result<(), DriverError> {
        if credential.backend != "mikrotik" {
            return Err(DriverError::Invalid(format!(
                "gateway {gateway_id} received {} credentials on a MikroTik agent",
                credential.backend
            )));
        }
        let base_url = Url::parse(&credential.base_url)
            .map_err(|error| DriverError::Invalid(format!("invalid RouterOS URL: {error}")))?;
        let target = build_target(
            gateway_id,
            base_url,
            credential.username,
            credential.password,
            credential.ca_certificate_pem.as_bytes(),
        )?;
        self.targets.write().await.insert(gateway_id, Arc::new(target));
        Ok(())
    }

    async fn observe(&self, gateway_id: Uuid) -> Result<ObservedGateway, DriverError> {
        let target = self.target(gateway_id).await?;
        let metadata = self
            .metadata
            .lock()
            .await
            .get(&gateway_id)
            .cloned()
            .ok_or_else(|| DriverError::Unavailable("gateway has not been reconciled yet".into()))?;
        let version = self.check_version(&target).await?;
        let interface = find_interface(&target, &metadata.interface_name).await?
            .ok_or_else(|| DriverError::Unavailable("managed WireGuard interface is missing".into()))?;
        let public_key = interface
            .get("public-key")
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::Apply("RouterOS did not report a WireGuard public key".into()))?;
        let actual_state_hash = live_state_hash(
            &target,
            gateway_id,
            &metadata.interface_name,
        )
        .await?;
        Ok(ObservedGateway {
            gateway_id,
            public_key: public_key.into(),
            listen_port: metadata.listen_port,
            actual_state_hash,
            backend_version: format!("RouterOS {version}"),
        })
    }

    async fn validate(&self, desired: &DesiredGatewayState) -> Result<(), DriverError> {
        validate_state(desired)?;
        let target = self.target(desired.gateway_id).await?;
        self.check_version(&target).await?;
        Ok(())
    }

    async fn apply(&self, desired: &DesiredGatewayState) -> Result<ApplyOutcome, DriverError> {
        validate_state(desired)?;
        let target = self.target(desired.gateway_id).await?;
        self.check_version(&target).await?;
        self.reconcile(&target, desired).await?;
        let actual_state_hash = live_state_hash(
            &target,
            desired.gateway_id,
            &desired.interface_name,
        )
        .await?;
        self.metadata.lock().await.insert(
            desired.gateway_id,
            Metadata {
                interface_name: desired.interface_name.clone(),
                listen_port: desired.listen_port,
            },
        );
        Ok(ApplyOutcome {
            revision: desired.revision,
            actual_state_hash,
        })
    }

    async fn flush_connections(&self, sources: &[std::net::Ipv4Addr]) -> Result<(), DriverError> {
        let targets = self.targets.read().await.values().cloned().collect::<Vec<_>>();
        for target in targets {
            let connections = target.list(&["ip", "firewall", "connection"]).await?;
            for connection in connections {
                let source = connection
                    .get("src-address")
                    .and_then(Value::as_str)
                    .and_then(|value| value.split(':').next());
                if source.is_some_and(|source| sources.iter().any(|wanted| source == wanted.to_string())) {
                    if let Some(id) = resource_id(&connection) {
                        target.delete(&["ip", "firewall", "connection"], id).await?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl RouterTarget {
    async fn list(&self, segments: &[&str]) -> Result<Vec<Value>, DriverError> {
        let value = self.request(Method::GET, segments, None).await?;
        value.as_array().cloned().ok_or_else(|| {
            DriverError::Apply(format!("RouterOS {} response was not a list", segments.join("/")))
        })
    }

    async fn get_object(&self, segments: &[&str]) -> Result<Value, DriverError> {
        let value = self.request(Method::GET, segments, None).await?;
        if value.is_object() {
            Ok(value)
        } else if let Some(first) = value.as_array().and_then(|values| values.first()) {
            Ok(first.clone())
        } else {
            Err(DriverError::Apply(format!(
                "RouterOS {} response was empty",
                segments.join("/")
            )))
        }
    }

    async fn post(&self, segments: &[&str], body: &Value) -> Result<Value, DriverError> {
        self.request(Method::PUT, segments, Some(body)).await
    }

    async fn patch(&self, segments: &[&str], body: &Value) -> Result<Value, DriverError> {
        self.request(Method::PATCH, segments, Some(body)).await
    }

    async fn delete(&self, segments: &[&str], id: &str) -> Result<(), DriverError> {
        let mut path = segments.to_vec();
        path.push(id);
        self.request(Method::DELETE, &path, None).await?;
        Ok(())
    }

    async fn post_path(&self, resource: &str, body: &Value) -> Result<Value, DriverError> {
        let segments: Vec<&str> = resource.trim_matches('/').split('/').collect();
        self.post(&segments, body).await
    }

    async fn request(
        &self,
        method: Method,
        segments: &[&str],
        body: Option<&Value>,
    ) -> Result<Value, DriverError> {
        let mut url = self.base_url.clone();
        {
            let mut path = url.path_segments_mut().map_err(|_| {
                DriverError::Invalid("RouterOS base URL cannot be used as a path base".into())
            })?;
            path.pop_if_empty();
            path.push("rest");
            for segment in segments {
                path.push(segment);
            }
        }
        let mut request = self
            .client
            .request(method, url.clone())
            .basic_auth(&self.username, Some(&self.password));
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| DriverError::Unavailable(format!("RouterOS {url}: {error}")))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| DriverError::Unavailable(format!("read RouterOS response: {error}")))?;
        if !status.is_success() {
            return Err(DriverError::Apply(format!(
                "RouterOS {} returned {}: {}",
                url.path(),
                status,
                String::from_utf8_lossy(&bytes)
            )));
        }
        if bytes.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|error| DriverError::Apply(format!("decode RouterOS response: {error}")))
        }
    }
}

async fn live_state_hash(
    target: &RouterTarget,
    gateway_id: Uuid,
    interface_name: &str,
) -> Result<String, DriverError> {
    let prefix = managed_prefix(gateway_id);
    let interface = find_interface(target, interface_name)
        .await?
        .ok_or_else(|| DriverError::Unavailable("managed WireGuard interface is missing".into()))?;
    let peers = target
        .list(&["interface", "wireguard", "peers"])
        .await?
        .into_iter()
        .filter(|value| value.get("interface").and_then(Value::as_str) == Some(interface_name))
        .collect::<Vec<_>>();
    let routes = managed_values(target, &["ip", "route"], &prefix).await?;
    let addresses = managed_values(target, &["ip", "address"], &prefix).await?;
    let filters = managed_values(target, &["ip", "firewall", "filter"], &prefix).await?;
    let address_lists =
        managed_values(target, &["ip", "firewall", "address-list"], &prefix).await?;
    let mut value = json!({
        "interface": interface,
        "peers": peers,
        "routes": routes,
        "addresses": addresses,
        "filters": filters,
        "address_lists": address_lists,
    });
    scrub_router_state(&mut value);
    sort_unordered_arrays(&mut value, &["peers", "routes", "addresses", "address_lists"]);
    let encoded = serde_json::to_vec(&value)
        .map_err(|error| DriverError::Apply(format!("encode RouterOS state: {error}")))?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

async fn managed_values(
    target: &RouterTarget,
    resource: &[&str],
    prefix: &str,
) -> Result<Vec<Value>, DriverError> {
    Ok(target
        .list(resource)
        .await?
        .into_iter()
        .filter(|value| {
            value
                .get("comment")
                .and_then(Value::as_str)
                .is_some_and(|comment| comment.starts_with(prefix))
        })
        .collect())
}

fn scrub_router_state(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for key in [
                ".id",
                "private-key",
                "last-handshake",
                "rx",
                "tx",
                "current-endpoint-address",
                "current-endpoint-port",
                "dynamic",
                "running",
                "packets",
                "bytes",
            ] {
                object.remove(key);
            }
            object.values_mut().for_each(scrub_router_state);
        }
        Value::Array(values) => values.iter_mut().for_each(scrub_router_state),
        _ => {}
    }
}

fn sort_unordered_arrays(value: &mut Value, keys: &[&str]) {
    let Some(object) = value.as_object_mut() else { return; };
    for key in keys {
        if let Some(Value::Array(values)) = object.get_mut(*key) {
            values.sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());
        }
    }
}

async fn ensure_interface(
    target: &RouterTarget,
    desired: &DesiredGatewayState,
    prefix: &str,
) -> Result<String, DriverError> {
    let body = json!({
        "name": desired.interface_name,
        "listen-port": desired.listen_port.to_string(),
        "mtu": desired.mtu.unwrap_or(1_420).to_string(),
        "comment": format!("{prefix}:exclusive-interface"),
        "disabled": "false",
    });
    if let Some(interface) = find_interface(target, &desired.interface_name).await? {
        let id = resource_id(&interface)
            .ok_or_else(|| DriverError::Apply("RouterOS interface has no .id".into()))?;
        let mut path = vec!["interface", "wireguard", id];
        target.patch(&path, &body).await?;
        path.clear();
        Ok(id.into())
    } else {
        let created = target.post(&["interface", "wireguard"], &body).await?;
        if let Some(id) = resource_id(&created) {
            Ok(id.into())
        } else {
            find_interface(target, &desired.interface_name)
                .await?
                .and_then(|value| resource_id(&value).map(str::to_owned))
                .ok_or_else(|| DriverError::Apply("created interface cannot be found".into()))
        }
    }
}

async fn find_interface(target: &RouterTarget, name: &str) -> Result<Option<Value>, DriverError> {
    Ok(target
        .list(&["interface", "wireguard"])
        .await?
        .into_iter()
        .find(|value| value.get("name").and_then(Value::as_str) == Some(name)))
}

async fn remove_managed(
    target: &RouterTarget,
    resource: &[&str],
    prefix: &str,
) -> Result<(), DriverError> {
    for value in target.list(resource).await? {
        if value
            .get("comment")
            .and_then(Value::as_str)
            .is_some_and(|comment| comment.starts_with(prefix))
        {
            if let Some(id) = resource_id(&value) {
                target.delete(resource, id).await?;
            }
        }
    }
    Ok(())
}

pub fn route_operations(desired: &DesiredGatewayState) -> Vec<RouterOperation> {
    let prefix = managed_prefix(desired.gateway_id);
    desired
        .peers
        .iter()
        .map(|peer| RouterOperation {
            resource: "/ip/route".into(),
            body: json!({
                "dst-address": format!("{}/32", peer.allowed_address),
                "gateway": desired.interface_name,
                "comment": format!("{prefix}:route:{}", peer.device_id),
            }),
        })
        .collect()
}

pub fn firewall_operations(
    desired: &DesiredGatewayState,
) -> Result<Vec<RouterOperation>, DriverError> {
    validate_state(desired)?;
    let prefix = managed_prefix(desired.gateway_id);
    let short = &desired.gateway_id.simple().to_string()[..8];
    let chain = format!("wm_{short}");
    let peer_list = format!("wm_{short}_peers");
    let destination_list = format!("wm_{short}_dst");
    let mut operations = Vec::new();
    for peer in &desired.peers {
        operations.push(address_list(
            &peer_list,
            &format!("{}/32", peer.allowed_address),
            &format!("{prefix}:peer-source:{}", peer.device_id),
        ));
    }
    for route in &desired.routes {
        operations.push(address_list(
            &destination_list,
            &route.to_string(),
            &format!("{prefix}:destination:{route}"),
        ));
    }
    operations.push(filter(json!({
        "chain": "forward",
        "in-interface": desired.interface_name,
        "action": "jump",
        "jump-target": chain,
        "comment": format!("{prefix}:jump"),
    })));
    operations.push(filter(json!({
        "chain": chain,
        "connection-state": "established,related",
        "action": "accept",
        "comment": format!("{prefix}:stateful-return"),
    })));
    operations.push(filter(json!({
        "chain": chain,
        "src-address-list": format!("!{peer_list}"),
        "action": "drop",
        "comment": format!("{prefix}:anti-spoof"),
    })));
    operations.push(filter(json!({
        "chain": chain,
        "dst-address-list": format!("!{destination_list}"),
        "action": "drop",
        "comment": format!("{prefix}:site-boundary"),
    })));

    let mut rules: Vec<_> = desired.acl_rules.iter().filter(|rule| rule.enabled).collect();
    rules.sort_by_key(|rule| (rule.position, rule.id));
    for rule in rules {
        let matching = desired
            .peers
            .iter()
            .filter(|peer| rule.subjects.matches(peer.user_id, &peer.group_ids))
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        let source_list = format!("wm_{short}_r{}", rule.position);
        for peer in matching {
            operations.push(address_list(
                &source_list,
                &format!("{}/32", peer.allowed_address),
                &format!("{prefix}:rule-source:{}:{}", rule.id, peer.device_id),
            ));
        }
        let mut body = json!({
            "chain": chain,
            "src-address-list": source_list,
            "dst-address": rule.destination.to_string(),
            "action": action_name(rule.action),
            "comment": format!("{prefix}:rule:{}", rule.id),
        });
        if rule.protocol != IpProtocol::Any {
            body["protocol"] = Value::String(protocol_name(rule.protocol).into());
        }
        if let Some(ports) = &rule.destination_ports {
            body["dst-port"] = Value::String(if ports.start == ports.end {
                ports.start.to_string()
            } else {
                format!("{}-{}", ports.start, ports.end)
            });
        }
        operations.push(filter(body));
    }
    operations.push(filter(json!({
        "chain": chain,
        "action": action_name(desired.acl_default),
        "comment": format!("{prefix}:default"),
    })));
    Ok(operations)
}

fn address_list(list: &str, address: &str, comment: &str) -> RouterOperation {
    RouterOperation {
        resource: "/ip/firewall/address-list".into(),
        body: json!({"list": list, "address": address, "comment": comment}),
    }
}

fn filter(body: Value) -> RouterOperation {
    RouterOperation {
        resource: "/ip/firewall/filter".into(),
        body,
    }
}

fn validate_state(desired: &DesiredGatewayState) -> Result<(), DriverError> {
    if desired.interface_name.is_empty() || desired.interface_name.len() > 63 {
        return Err(DriverError::Invalid("invalid RouterOS interface name".into()));
    }
    if desired.listen_port == 0 || desired.routes.is_empty() {
        return Err(DriverError::Invalid(
            "listen port and protected routes are required".into(),
        ));
    }
    for peer in &desired.peers {
        wiremesh_domain::validate_wireguard_public_key(&peer.public_key)
            .map_err(|error| DriverError::Invalid(error.to_string()))?;
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

fn supported_version(version: &str) -> bool {
    let numeric = version.split_whitespace().next().unwrap_or(version);
    let mut components = numeric.split('.').filter_map(|value| {
        value
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .ok()
    });
    let major = components.next().unwrap_or(0);
    let minor = components.next().unwrap_or(0);
    major > 7 || (major == 7 && minor >= 15)
}

fn managed_prefix(gateway_id: Uuid) -> String {
    format!("wiremesh:{gateway_id}")
}

fn resource_id(value: &Value) -> Option<&str> {
    value.get(".id").and_then(Value::as_str)
}

fn action_name(action: AclAction) -> &'static str {
    match action {
        AclAction::Allow => "accept",
        AclAction::Deny => "drop",
    }
}

fn protocol_name(protocol: IpProtocol) -> &'static str {
    match protocol {
        IpProtocol::Any => "",
        IpProtocol::Tcp => "tcp",
        IpProtocol::Udp => "udp",
        IpProtocol::Icmp => "icmp",
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::Ipv4Addr};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use wiremesh_domain::{AclRule, AclSubjects, DesiredPeer, PortRange};

    use super::*;

    fn desired() -> DesiredGatewayState {
        let user = Uuid::new_v4();
        DesiredGatewayState {
            gateway_id: Uuid::nil(),
            revision: 9,
            interface_name: "wiremesh".into(),
            listen_port: 51_820,
            mtu: Some(1_420),
            compatibility_address: Some(Ipv4Addr::new(10, 20, 0, 1)),
            routes: vec!["10.50.0.0/16".parse().unwrap()],
            peers: vec![DesiredPeer {
                device_id: Uuid::new_v4(),
                user_id: user,
                public_key: STANDARD.encode([4_u8; 32]),
                allowed_address: Ipv4Addr::new(10, 20, 0, 2),
                group_ids: BTreeSet::new(),
            }],
            acl_default: AclAction::Deny,
            acl_rules: vec![AclRule {
                id: Uuid::new_v4(),
                position: 10,
                action: AclAction::Allow,
                destination: "10.50.1.0/24".parse().unwrap(),
                protocol: IpProtocol::Tcp,
                destination_ports: Some(PortRange { start: 443, end: 443 }),
                subjects: AclSubjects {
                    users: BTreeSet::from([user]),
                    groups: BTreeSet::new(),
                },
                enabled: true,
            }],
            terminate_sources: vec![],
        }
    }

    #[test]
    fn rejects_old_routeros_versions() {
        assert!(!supported_version("7.14.3 (stable)"));
        assert!(supported_version("7.15"));
        assert!(supported_version("8.0beta2"));
    }

    #[test]
    fn plans_scoped_routes_and_ordered_firewall_rules() {
        let desired = desired();
        let routes = route_operations(&desired);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].body["dst-address"], "10.20.0.2/32");
        assert_eq!(routes[0].body["gateway"], "wiremesh");
        let firewall = firewall_operations(&desired).unwrap();
        let descriptions = firewall
            .iter()
            .filter_map(|operation| operation.body.get("comment").and_then(Value::as_str))
            .collect::<Vec<_>>();
        let established = descriptions.iter().position(|value| value.ends_with("stateful-return")).unwrap();
        let rule = descriptions.iter().position(|value| value.contains(":rule:")).unwrap();
        let default = descriptions.iter().position(|value| value.ends_with(":default")).unwrap();
        assert!(established < rule && rule < default);
    }
}
