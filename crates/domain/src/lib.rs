//! WireMesh's side-effect-free domain rules.
//!
//! This crate intentionally contains no database, HTTP, or router code. The
//! controller and every gateway backend use the same validation and rendering
//! rules so that policy does not drift between implementations.

pub mod acl;
pub mod config;
pub mod identity;
pub mod network;
pub mod state;

pub use acl::*;
pub use config::*;
pub use identity::*;
pub use network::*;
pub use state::*;
