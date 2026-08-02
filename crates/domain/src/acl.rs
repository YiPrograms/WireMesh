use std::{collections::BTreeSet, net::Ipv4Addr, ops::RangeInclusive};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn values(&self) -> RangeInclusive<u16> {
        self.start..=self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclSubjects {
    pub users: BTreeSet<Uuid>,
    pub groups: BTreeSet<Uuid>,
}

impl AclSubjects {
    pub fn everyone() -> Self {
        Self {
            users: BTreeSet::new(),
            groups: BTreeSet::new(),
        }
    }

    pub fn matches(&self, user_id: Uuid, group_ids: &BTreeSet<Uuid>) -> bool {
        (self.users.is_empty() && self.groups.is_empty())
            || self.users.contains(&user_id)
            || !self.groups.is_disjoint(group_ids)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub id: Uuid,
    pub position: u32,
    pub action: AclAction,
    pub destination: Ipv4Net,
    pub protocol: IpProtocol,
    pub destination_ports: Option<PortRange>,
    pub subjects: AclSubjects,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketContext {
    pub user_id: Uuid,
    pub group_ids: BTreeSet<Uuid>,
    pub destination: Ipv4Addr,
    pub protocol: IpProtocol,
    pub destination_port: Option<u16>,
}

impl AclRule {
    pub fn matches(&self, packet: &PacketContext) -> bool {
        if !self.enabled
            || !self.destination.contains(&packet.destination)
            || !self.subjects.matches(packet.user_id, &packet.group_ids)
            || (self.protocol != IpProtocol::Any && self.protocol != packet.protocol)
        {
            return false;
        }
        match (&self.destination_ports, packet.destination_port) {
            (None, _) => true,
            (Some(range), Some(port)) => range.values().contains(&port),
            (Some(_), None) => false,
        }
    }
}

pub fn evaluate_acl(
    rules: &[AclRule],
    default_action: AclAction,
    packet: &PacketContext,
) -> AclAction {
    let mut ordered: Vec<_> = rules.iter().collect();
    ordered.sort_by_key(|rule| (rule.position, rule.action != AclAction::Deny, rule.id));
    ordered
        .into_iter()
        .find(|rule| rule.matches(packet))
        .map(|rule| rule.action)
        .unwrap_or(default_action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_match_wins_across_user_and_group_rules() {
        let user = Uuid::new_v4();
        let group = Uuid::new_v4();
        let packet = PacketContext {
            user_id: user,
            group_ids: BTreeSet::from([group]),
            destination: "10.10.0.8".parse().unwrap(),
            protocol: IpProtocol::Tcp,
            destination_port: Some(22),
        };
        let rules = vec![
            AclRule {
                id: Uuid::new_v4(),
                position: 20,
                action: AclAction::Allow,
                destination: "10.10.0.0/24".parse().unwrap(),
                protocol: IpProtocol::Tcp,
                destination_ports: Some(PortRange { start: 22, end: 22 }),
                subjects: AclSubjects {
                    users: BTreeSet::new(),
                    groups: BTreeSet::from([group]),
                },
                enabled: true,
            },
            AclRule {
                id: Uuid::new_v4(),
                position: 10,
                action: AclAction::Deny,
                destination: "10.10.0.8/32".parse().unwrap(),
                protocol: IpProtocol::Any,
                destination_ports: None,
                subjects: AclSubjects {
                    users: BTreeSet::from([user]),
                    groups: BTreeSet::new(),
                },
                enabled: true,
            },
        ];
        assert_eq!(
            evaluate_acl(&rules, AclAction::Allow, &packet),
            AclAction::Deny
        );
    }

    #[test]
    fn icmp_uses_normal_default() {
        let packet = PacketContext {
            user_id: Uuid::new_v4(),
            group_ids: BTreeSet::new(),
            destination: "10.10.0.8".parse().unwrap(),
            protocol: IpProtocol::Icmp,
            destination_port: None,
        };
        assert_eq!(evaluate_acl(&[], AclAction::Deny, &packet), AclAction::Deny);
    }
}
