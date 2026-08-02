use std::{collections::BTreeSet, net::Ipv4Addr};

use ipnet::Ipv4Net;
use thiserror::Error;
use uuid::Uuid;
use wiremesh_domain::{
    AclAction, AclRule, AclSubjects, DesiredGatewayState, DesiredPeer, IpProtocol, PortRange,
};
use wiremesh_proto::v1 as proto;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid {field}: {message}")]
    Invalid {
        field: &'static str,
        message: String,
    },
}

pub fn desired_to_proto(value: &DesiredGatewayState) -> proto::DesiredSnapshot {
    proto::DesiredSnapshot {
        gateway_id: value.gateway_id.to_string(),
        revision: value.revision,
        interface_name: value.interface_name.clone(),
        listen_port: u32::from(value.listen_port),
        mtu: value.mtu.map(u32::from),
        compatibility_address: value.compatibility_address.map(|address| address.to_string()),
        routes: value.routes.iter().map(ToString::to_string).collect(),
        peers: value
            .peers
            .iter()
            .map(|peer| proto::DesiredPeer {
                device_id: peer.device_id.to_string(),
                user_id: peer.user_id.to_string(),
                public_key: peer.public_key.clone(),
                allowed_address: peer.allowed_address.to_string(),
                group_ids: peer.group_ids.iter().map(ToString::to_string).collect(),
            })
            .collect(),
        acl_default: action_name(value.acl_default).into(),
        acl_rules: value
            .acl_rules
            .iter()
            .map(|rule| proto::AclRule {
                id: rule.id.to_string(),
                position: rule.position,
                action: action_name(rule.action).into(),
                destination: rule.destination.to_string(),
                protocol: protocol_name(rule.protocol).into(),
                port_start: rule.destination_ports.as_ref().map(|ports| u32::from(ports.start)),
                port_end: rule.destination_ports.as_ref().map(|ports| u32::from(ports.end)),
                user_ids: rule.subjects.users.iter().map(ToString::to_string).collect(),
                group_ids: rule.subjects.groups.iter().map(ToString::to_string).collect(),
                enabled: rule.enabled,
            })
            .collect(),
        terminate_sources: value.terminate_sources.iter().map(ToString::to_string).collect(),
        credential_envelope: Vec::new(),
    }
}

pub fn desired_from_proto(value: proto::DesiredSnapshot) -> Result<DesiredGatewayState, ProtocolError> {
    let mut state = DesiredGatewayState {
        gateway_id: uuid(&value.gateway_id, "gateway_id")?,
        revision: value.revision,
        interface_name: value.interface_name,
        listen_port: number_u16(value.listen_port, "listen_port")?,
        mtu: value.mtu.map(|number| number_u16(number, "mtu")).transpose()?,
        compatibility_address: value
            .compatibility_address
            .map(|address| ipv4(&address, "compatibility_address"))
            .transpose()?,
        routes: value
            .routes
            .into_iter()
            .map(|route| ipv4_net(&route, "routes"))
            .collect::<Result<_, _>>()?,
        peers: value
            .peers
            .into_iter()
            .map(|peer| {
                Ok(DesiredPeer {
                    device_id: uuid(&peer.device_id, "peer.device_id")?,
                    user_id: uuid(&peer.user_id, "peer.user_id")?,
                    public_key: peer.public_key,
                    allowed_address: ipv4(&peer.allowed_address, "peer.allowed_address")?,
                    group_ids: peer
                        .group_ids
                        .into_iter()
                        .map(|id| uuid(&id, "peer.group_ids"))
                        .collect::<Result<BTreeSet<_>, _>>()?,
                })
            })
            .collect::<Result<_, ProtocolError>>()?,
        acl_default: action(&value.acl_default, "acl_default")?,
        acl_rules: value
            .acl_rules
            .into_iter()
            .map(|rule| {
                let ports = match (rule.port_start, rule.port_end) {
                    (None, None) => None,
                    (Some(start), Some(end)) => {
                        let start = number_u16(start, "acl.port_start")?;
                        let end = number_u16(end, "acl.port_end")?;
                        if start > end {
                            return Err(invalid("acl.ports", "start exceeds end"));
                        }
                        Some(PortRange { start, end })
                    }
                    _ => return Err(invalid("acl.ports", "both bounds are required")),
                };
                Ok(AclRule {
                    id: uuid(&rule.id, "acl.id")?,
                    position: rule.position,
                    action: action(&rule.action, "acl.action")?,
                    destination: ipv4_net(&rule.destination, "acl.destination")?,
                    protocol: protocol(&rule.protocol)?,
                    destination_ports: ports,
                    subjects: AclSubjects {
                        users: rule
                            .user_ids
                            .into_iter()
                            .map(|id| uuid(&id, "acl.user_ids"))
                            .collect::<Result<_, _>>()?,
                        groups: rule
                            .group_ids
                            .into_iter()
                            .map(|id| uuid(&id, "acl.group_ids"))
                            .collect::<Result<_, _>>()?,
                    },
                    enabled: rule.enabled,
                })
            })
            .collect::<Result<_, ProtocolError>>()?,
        terminate_sources: value
            .terminate_sources
            .into_iter()
            .map(|source| ipv4(&source, "terminate_sources"))
            .collect::<Result<_, _>>()?,
    };
    state.canonicalize();
    Ok(state)
}

fn action_name(action: AclAction) -> &'static str {
    match action {
        AclAction::Allow => "allow",
        AclAction::Deny => "deny",
    }
}

fn protocol_name(protocol: IpProtocol) -> &'static str {
    match protocol {
        IpProtocol::Any => "any",
        IpProtocol::Tcp => "tcp",
        IpProtocol::Udp => "udp",
        IpProtocol::Icmp => "icmp",
    }
}

fn action(value: &str, field: &'static str) -> Result<AclAction, ProtocolError> {
    match value {
        "allow" => Ok(AclAction::Allow),
        "deny" => Ok(AclAction::Deny),
        _ => Err(invalid(field, "expected allow or deny")),
    }
}

fn protocol(value: &str) -> Result<IpProtocol, ProtocolError> {
    match value {
        "any" => Ok(IpProtocol::Any),
        "tcp" => Ok(IpProtocol::Tcp),
        "udp" => Ok(IpProtocol::Udp),
        "icmp" => Ok(IpProtocol::Icmp),
        _ => Err(invalid("acl.protocol", "unsupported protocol")),
    }
}

fn uuid(value: &str, field: &'static str) -> Result<Uuid, ProtocolError> {
    value.parse().map_err(|error| invalid(field, error))
}

fn ipv4(value: &str, field: &'static str) -> Result<Ipv4Addr, ProtocolError> {
    value.parse().map_err(|error| invalid(field, error))
}

fn ipv4_net(value: &str, field: &'static str) -> Result<Ipv4Net, ProtocolError> {
    value.parse().map_err(|error| invalid(field, error))
}

fn number_u16(value: u32, field: &'static str) -> Result<u16, ProtocolError> {
    u16::try_from(value).map_err(|error| invalid(field, error))
}

fn invalid(field: &'static str, error: impl ToString) -> ProtocolError {
    ProtocolError::Invalid {
        field,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_snapshot_round_trips() {
        let state = DesiredGatewayState {
            gateway_id: Uuid::new_v4(),
            revision: 7,
            interface_name: "wm0".into(),
            listen_port: 51_820,
            mtu: Some(1_420),
            compatibility_address: None,
            routes: vec!["10.0.0.0/8".parse().unwrap()],
            peers: vec![DesiredPeer {
                device_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                public_key: "key".into(),
                allowed_address: "10.20.0.2".parse().unwrap(),
                group_ids: BTreeSet::from([Uuid::new_v4()]),
            }],
            acl_default: AclAction::Deny,
            acl_rules: vec![],
            terminate_sources: vec![],
        };
        assert_eq!(desired_from_proto(desired_to_proto(&state)).unwrap(), state);
    }
}
