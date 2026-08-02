#![allow(clippy::derive_partial_eq_without_eq)]

pub mod v1 {
    tonic::include_proto!("wiremesh.agent.v1");
}

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;
