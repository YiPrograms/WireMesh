pub mod api;
pub mod auth;
pub mod db;
pub mod desired;
pub mod error;
pub mod federated;
pub mod grpc;
pub mod identity;
pub mod models;
pub mod migration;
pub mod mail;
pub mod router_target;
pub mod secrets;
pub mod service;
pub mod user_import;

use sqlx::SqlitePool;
use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub secrets: secrets::SecretBox,
    pub web_directory: Option<PathBuf>,
}
