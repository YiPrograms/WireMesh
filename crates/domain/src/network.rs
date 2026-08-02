use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddrV4},
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRoute {
    pub gateway_id: Uuid,
    pub site_id: Uuid,
    pub cidr: Ipv4Net,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkError {
    #[error("client pool must contain at least four addresses")]
    PoolTooSmall,
    #[error("client pool is exhausted")]
    PoolExhausted,
    #[error(
        "route {left} on gateway {left_gateway} overlaps route {right} on gateway {right_gateway}"
    )]
    CrossGatewayOverlap {
        left: Ipv4Net,
        right: Ipv4Net,
        left_gateway: Uuid,
        right_gateway: Uuid,
    },
    #[error("client-pool routes may belong to only one gateway")]
    MultipleClientRoutingGateways,
    #[error("new pool must contain the old pool for an in-place expansion")]
    NotAnExpansion,
    #[error("public endpoint {0} is inside a routed VPN prefix")]
    EndpointInsideRoute(SocketAddrV4),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientPool {
    pub cidr: Ipv4Net,
}

impl ClientPool {
    pub fn new(cidr: Ipv4Net) -> Result<Self, NetworkError> {
        if address_count(cidr) < 4 {
            return Err(NetworkError::PoolTooSmall);
        }
        Ok(Self { cidr })
    }

    pub fn network(&self) -> Ipv4Addr {
        self.cidr.network()
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        self.cidr.broadcast()
    }

    pub fn compatibility_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network()) + 1)
    }

    pub fn usable_capacity(&self) -> u64 {
        address_count(self.cidr).saturating_sub(3)
    }

    pub fn contains_allocatable(&self, address: Ipv4Addr) -> bool {
        self.cidr.contains(&address)
            && address != self.network()
            && address != self.broadcast()
            && address != self.compatibility_address()
    }

    pub fn allocate(
        &self,
        allocated_or_quarantined: &BTreeSet<Ipv4Addr>,
    ) -> Result<Ipv4Addr, NetworkError> {
        let first = u32::from(self.network()).saturating_add(2);
        let last = u32::from(self.broadcast());
        for raw in first..last {
            let address = Ipv4Addr::from(raw);
            if !allocated_or_quarantined.contains(&address) {
                return Ok(address);
            }
        }
        Err(NetworkError::PoolExhausted)
    }

    pub fn validate_expansion(&self, new_pool: ClientPool) -> Result<(), NetworkError> {
        if new_pool.cidr.prefix_len() > self.cidr.prefix_len()
            || !new_pool.cidr.contains(&self.network())
            || !new_pool.cidr.contains(&self.broadcast())
        {
            return Err(NetworkError::NotAnExpansion);
        }
        Ok(())
    }
}

fn address_count(network: Ipv4Net) -> u64 {
    1_u64 << (32 - u32::from(network.prefix_len()))
}

pub fn networks_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

/// Validates client-side route determinism.
///
/// Routes may overlap on the same gateway because they resolve to the same peer.
/// A route intersecting the client pool is treated as client-to-client routing;
/// every such route must be owned by a single gateway.
pub fn validate_gateway_routes(
    client_pool: ClientPool,
    routes: &[GatewayRoute],
) -> Result<(), NetworkError> {
    let mut client_router = None;
    for (index, left) in routes.iter().enumerate() {
        if networks_overlap(left.cidr, client_pool.cidr) {
            match client_router {
                None => client_router = Some(left.gateway_id),
                Some(id) if id == left.gateway_id => {}
                Some(_) => return Err(NetworkError::MultipleClientRoutingGateways),
            }
        }
        for right in routes.iter().skip(index + 1) {
            if left.gateway_id != right.gateway_id && networks_overlap(left.cidr, right.cidr) {
                return Err(NetworkError::CrossGatewayOverlap {
                    left: left.cidr,
                    right: right.cidr,
                    left_gateway: left.gateway_id,
                    right_gateway: right.gateway_id,
                });
            }
        }
    }
    Ok(())
}

/// Rejects literal gateway endpoints that would be captured by any client
/// `AllowedIPs` route. Hostnames cannot be resolved safely at configuration
/// time and must be kept outside protected prefixes by the administrator.
pub fn validate_endpoint_routes(
    routes: &[GatewayRoute],
    endpoints: &[SocketAddrV4],
) -> Result<(), NetworkError> {
    for endpoint in endpoints {
        if routes
            .iter()
            .any(|route| route.cidr.contains(endpoint.ip()))
        {
            return Err(NetworkError::EndpointInsideRoute(*endpoint));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(value: &str) -> Ipv4Net {
        value.parse().unwrap()
    }

    #[test]
    fn reserves_network_broadcast_and_first_usable() {
        let pool = ClientPool::new(net("10.20.0.0/29")).unwrap();
        assert_eq!(pool.compatibility_address(), Ipv4Addr::new(10, 20, 0, 1));
        assert_eq!(pool.usable_capacity(), 5);
        assert_eq!(
            pool.allocate(&BTreeSet::new()).unwrap(),
            Ipv4Addr::new(10, 20, 0, 2)
        );
    }

    #[test]
    fn allocator_never_reuses_quarantine() {
        let pool = ClientPool::new(net("10.20.0.0/29")).unwrap();
        let occupied = BTreeSet::from([Ipv4Addr::new(10, 20, 0, 2), Ipv4Addr::new(10, 20, 0, 3)]);
        assert_eq!(
            pool.allocate(&occupied).unwrap(),
            Ipv4Addr::new(10, 20, 0, 4)
        );
    }

    #[test]
    fn rejects_cross_gateway_overlap() {
        let site_a = Uuid::new_v4();
        let site_b = Uuid::new_v4();
        let gateway_a = Uuid::new_v4();
        let gateway_b = Uuid::new_v4();
        let routes = vec![
            GatewayRoute {
                gateway_id: gateway_a,
                site_id: site_a,
                cidr: net("10.10.0.0/16"),
            },
            GatewayRoute {
                gateway_id: gateway_b,
                site_id: site_b,
                cidr: net("10.10.1.0/24"),
            },
        ];
        assert!(matches!(
            validate_gateway_routes(ClientPool::new(net("10.20.0.0/16")).unwrap(), &routes),
            Err(NetworkError::CrossGatewayOverlap { .. })
        ));
    }

    #[test]
    fn permits_client_routes_on_only_one_gateway() {
        let gateway = Uuid::new_v4();
        let routes = vec![GatewayRoute {
            gateway_id: gateway,
            site_id: Uuid::new_v4(),
            cidr: net("10.20.0.0/24"),
        }];
        assert!(
            validate_gateway_routes(ClientPool::new(net("10.20.0.0/16")).unwrap(), &routes).is_ok()
        );
    }

    #[test]
    fn validates_only_containing_supernets_as_expansion() {
        let pool = ClientPool::new(net("10.20.0.0/24")).unwrap();
        assert!(
            pool.validate_expansion(ClientPool::new(net("10.20.0.0/23")).unwrap())
                .is_ok()
        );
        assert_eq!(
            pool.validate_expansion(ClientPool::new(net("10.21.0.0/16")).unwrap()),
            Err(NetworkError::NotAnExpansion)
        );
    }

    #[test]
    fn rejects_literal_endpoints_captured_by_a_client_route() {
        let routes = vec![GatewayRoute {
            gateway_id: Uuid::new_v4(),
            site_id: Uuid::new_v4(),
            cidr: net("10.60.0.0/16"),
        }];
        let endpoint = SocketAddrV4::new(Ipv4Addr::new(10, 60, 10, 1), 51_820);
        assert_eq!(
            validate_endpoint_routes(&routes, &[endpoint]),
            Err(NetworkError::EndpointInsideRoute(endpoint))
        );
    }
}
