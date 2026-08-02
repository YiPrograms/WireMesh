use std::{path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;
use wiremesh_agent_core::runtime::{AgentConfig, run_forever};
use wiremesh_agent_linux::LinuxDriver;

#[derive(Parser)]
#[command(name = "wiremesh-agent-linux", version)]
struct Cli {
    #[arg(long, env = "WIREMESH_CONTROLLER_URL")]
    controller_url: String,
    #[arg(long, env = "WIREMESH_CONTROLLER_SERVER_NAME")]
    server_name: String,
    #[arg(long, env = "WIREMESH_CONTROLLER_CA")]
    ca_certificate: PathBuf,
    #[arg(long, env = "WIREMESH_AGENT_ID")]
    agent_id: Uuid,
    #[arg(long, env = "WIREMESH_AGENT_SECRET", hide_env_values = true)]
    secret: String,
    #[arg(
        long,
        env = "WIREMESH_STATE_DIRECTORY",
        default_value = "/var/lib/wiremesh"
    )]
    state_directory: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wiremesh_agent_linux=info,wiremesh_agent_core=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();
    let cli = Cli::parse();
    let driver_state = cli.state_directory.join("linux");
    let cache = cli.state_directory.join("desired");
    let driver = Arc::new(LinuxDriver::system(driver_state));
    run_forever(
        AgentConfig {
            controller_url: cli.controller_url,
            server_name: cli.server_name,
            ca_certificate: cli.ca_certificate,
            agent_id: cli.agent_id,
            secret: cli.secret,
            cache_directory: cache,
            capabilities: vec![
                "wireguard".into(),
                "ipv4-routes".into(),
                "nftables".into(),
                "conntrack-flush".into(),
                "scheduled-migration".into(),
            ],
            heartbeat_interval: Duration::from_secs(10),
        },
        driver,
    )
    .await
}
