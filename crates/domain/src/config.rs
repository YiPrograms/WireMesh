use std::net::Ipv4Addr;

use base64::{Engine, engine::general_purpose::STANDARD};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const PRIVATE_KEY_PLACEHOLDER: &str = "<CLIENT_PRIVATE_KEY>";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClientOptions {
    pub dns_servers: Vec<Ipv4Addr>,
    pub search_domains: Vec<String>,
    pub mtu: Option<u16>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientPeer {
    pub site_id: Uuid,
    pub site_name: String,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<Ipv4Net>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfigModel {
    pub device_id: Uuid,
    pub device_name: String,
    pub revision: u64,
    pub address: Ipv4Addr,
    pub options: ClientOptions,
    pub peers: Vec<ClientPeer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigChangeKind {
    Address,
    Options,
    PeerAdded,
    PeerRemoved,
    PeerChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigChange {
    pub kind: ConfigChangeKind,
    pub site_id: Option<Uuid>,
    pub description: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("public key must be base64-encoded 32 bytes")]
    InvalidPublicKey,
    #[error("peer {0} has no routes")]
    PeerWithoutRoutes(String),
}

pub fn validate_wireguard_public_key(value: &str) -> Result<(), ConfigError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ConfigError::InvalidPublicKey)?;
    if decoded.len() != 32 {
        return Err(ConfigError::InvalidPublicKey);
    }
    Ok(())
}

impl ClientConfigModel {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for peer in &self.peers {
            validate_wireguard_public_key(&peer.public_key)?;
            if peer.allowed_ips.is_empty() {
                return Err(ConfigError::PeerWithoutRoutes(peer.site_name.clone()));
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        let mut semantic = self.clone();
        semantic.revision = 0;
        let serialized = serde_json::to_vec(&semantic).expect("config model is serializable");
        format!("{:x}", Sha256::digest(serialized))
    }

    pub fn render(&self, private_key: Option<&str>) -> String {
        let mut output = String::new();
        output.push_str("[Interface]\n");
        output.push_str("PrivateKey = ");
        output.push_str(private_key.unwrap_or(PRIVATE_KEY_PLACEHOLDER));
        output.push('\n');
        output.push_str(&format!("Address = {}/32\n", self.address));
        if !self.options.dns_servers.is_empty() || !self.options.search_domains.is_empty() {
            let mut values: Vec<String> = self
                .options
                .dns_servers
                .iter()
                .map(ToString::to_string)
                .collect();
            values.extend(self.options.search_domains.iter().cloned());
            output.push_str(&format!("DNS = {}\n", values.join(", ")));
        }
        if let Some(mtu) = self.options.mtu {
            output.push_str(&format!("MTU = {mtu}\n"));
        }

        let mut peers = self.peers.clone();
        peers.sort_by_key(|peer| (peer.site_name.to_lowercase(), peer.site_id));
        for peer in peers {
            output.push_str("\n[Peer]\n");
            output.push_str(&format!("# {}\n", peer.site_name));
            output.push_str(&format!("PublicKey = {}\n", peer.public_key));
            output.push_str(&format!("Endpoint = {}\n", peer.endpoint));
            let routes = peer
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            output.push_str(&format!("AllowedIPs = {}\n", routes.join(", ")));
            if let Some(keepalive) = self.options.persistent_keepalive {
                output.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
            }
        }
        output
    }

    pub fn diff(&self, current: &Self) -> Vec<ConfigChange> {
        let mut changes = Vec::new();
        if self.address != current.address {
            changes.push(ConfigChange {
                kind: ConfigChangeKind::Address,
                site_id: None,
                description: format!(
                    "address changed from {} to {}",
                    self.address, current.address
                ),
            });
        }
        if self.options != current.options {
            changes.push(ConfigChange {
                kind: ConfigChangeKind::Options,
                site_id: None,
                description: "global client options changed".into(),
            });
        }
        for old in &self.peers {
            match current
                .peers
                .iter()
                .find(|peer| peer.site_id == old.site_id)
            {
                None => changes.push(ConfigChange {
                    kind: ConfigChangeKind::PeerRemoved,
                    site_id: Some(old.site_id),
                    description: format!("site {} was removed", old.site_name),
                }),
                Some(new) if new != old => changes.push(ConfigChange {
                    kind: ConfigChangeKind::PeerChanged,
                    site_id: Some(old.site_id),
                    description: format!("site {} peer settings changed", old.site_name),
                }),
                Some(_) => {}
            }
        }
        for new in &current.peers {
            if !self.peers.iter().any(|peer| peer.site_id == new.site_id) {
                changes.push(ConfigChange {
                    kind: ConfigChangeKind::PeerAdded,
                    site_id: Some(new.site_id),
                    description: format!("site {} was added", new.site_name),
                });
            }
        }
        changes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    fn model() -> ClientConfigModel {
        ClientConfigModel {
            device_id: Uuid::nil(),
            device_name: "phone".into(),
            revision: 1,
            address: "10.20.0.2".parse().unwrap(),
            options: ClientOptions {
                persistent_keepalive: Some(25),
                ..Default::default()
            },
            peers: vec![ClientPeer {
                site_id: Uuid::from_u128(1),
                site_name: "Site A".into(),
                public_key: key(7),
                endpoint: "vpn.example.com:51820".into(),
                allowed_ips: vec!["10.10.0.0/16".parse().unwrap()],
            }],
        }
    }

    #[test]
    fn placeholder_is_rendered_without_a_private_key() {
        let rendered = model().render(None);
        assert!(rendered.contains("PrivateKey = <CLIENT_PRIVATE_KEY>"));
        assert!(rendered.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn diffs_client_visible_peer_changes() {
        let old = model();
        let mut current = old.clone();
        current.peers[0].endpoint = "new.example.com:51820".into();
        assert_eq!(current.diff(&old).len(), 1);
        assert_eq!(old.diff(&current)[0].kind, ConfigChangeKind::PeerChanged);
    }
}
