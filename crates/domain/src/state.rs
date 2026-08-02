use std::{collections::BTreeSet, net::Ipv4Addr};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AclAction, AclRule};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredPeer {
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub allowed_address: Ipv4Addr,
    /// Effective canonical groups, included so agents can compile group ACLs
    /// without needing access to the identity database.
    pub group_ids: BTreeSet<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredGatewayState {
    pub gateway_id: Uuid,
    pub revision: u64,
    pub interface_name: String,
    pub listen_port: u16,
    pub mtu: Option<u16>,
    /// Reserved first-usable client-pool address used only by RouterOS
    /// installations whose acceptance test requires a numbered interface.
    pub compatibility_address: Option<Ipv4Addr>,
    pub routes: Vec<Ipv4Net>,
    pub peers: Vec<DesiredPeer>,
    pub acl_default: AclAction,
    pub acl_rules: Vec<AclRule>,
    pub terminate_sources: Vec<Ipv4Addr>,
}

impl DesiredGatewayState {
    pub fn canonicalize(&mut self) {
        self.routes.sort();
        self.routes.dedup();
        self.peers
            .sort_by_key(|peer| (peer.allowed_address, peer.device_id));
        self.acl_rules.sort_by_key(|rule| (rule.position, rule.id));
        self.terminate_sources.sort();
        self.terminate_sources.dedup();
    }
}
