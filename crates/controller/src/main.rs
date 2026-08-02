use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use wiremesh_controller::{AppState, api, auth, db, grpc, models, service};

#[derive(Debug, Parser)]
#[command(name = "wiremesh-controller", version)]
struct Cli {
    #[arg(
        long,
        env = "WIREMESH_DATABASE_URL",
        default_value = "sqlite://data/wiremesh.db"
    )]
    database_url: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, env = "WIREMESH_LISTEN", default_value = "0.0.0.0:8080")]
        listen: SocketAddr,
        #[arg(
            long,
            env = "WIREMESH_AGENT_LISTEN",
            default_value = "0.0.0.0:8443"
        )]
        agent_listen: SocketAddr,
        #[arg(long, env = "WIREMESH_AGENT_TLS_CERT")]
        agent_tls_cert: Option<PathBuf>,
        #[arg(long, env = "WIREMESH_AGENT_TLS_KEY")]
        agent_tls_key: Option<PathBuf>,
        #[arg(
            long,
            env = "WIREMESH_MASTER_KEY_FILE",
            default_value = "/run/secrets/wiremesh_master_key"
        )]
        master_key_file: PathBuf,
        #[arg(long, env = "WIREMESH_WEB_DIRECTORY", default_value = "/app/web")]
        web_directory: PathBuf,
    },
    /// Check database connectivity and apply schema migrations.
    Migrate,
    /// Create or recover a local administrator and print a seven-day enrollment token.
    BootstrapAdmin {
        #[arg(long)]
        email: String,
        #[arg(long)]
        name: String,
    },
    /// Provision an outbound gateway agent and print its secret exactly once.
    CreateAgent {
        #[arg(long)]
        name: String,
        #[arg(long, value_enum)]
        kind: AgentKind,
    },
    /// Generate a new 256-bit master key. Store it outside the SQLite volume.
    GenerateMasterKey,
    /// Create a transactionally consistent SQLite snapshot without stopping the controller.
    Backup {
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum AgentKind {
    Linux,
    Mikrotik,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wiremesh_controller=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Serve {
        listen: "0.0.0.0:8080".parse()?,
        agent_listen: "0.0.0.0:8443".parse()?,
        agent_tls_cert: None,
        agent_tls_key: None,
        master_key_file: "/run/secrets/wiremesh_master_key".into(),
        web_directory: "/app/web".into(),
    });
    if matches!(command, Command::GenerateMasterKey) {
        println!("{}", wiremesh_controller::secrets::generate_master_key());
        return Ok(());
    }
    let pool = db::connect(&cli.database_url).await?;
    match command {
        Command::Migrate => {
            tracing::info!("database migrations complete");
            Ok(())
        }
        Command::BootstrapAdmin { email, name } => {
            let result = auth::bootstrap_admin(&pool, &email, &name).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Command::CreateAgent { name, kind } => {
            let kind = match kind {
                AgentKind::Linux => models::GatewayKindRequest::Linux,
                AgentKind::Mikrotik => models::GatewayKindRequest::Mikrotik,
            };
            let result = service::create_agent(&pool, models::CreateAgentRequest { name, kind }).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Command::GenerateMasterKey => unreachable!("handled before database initialization"),
        Command::Backup { output } => {
            if output.exists() {
                anyhow::bail!("refusing to overwrite existing backup {}", output.display());
            }
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            tokio::fs::create_dir_all(parent).await?;
            let output = parent
                .canonicalize()?
                .join(output.file_name().context("backup output must name a file")?);
            sqlx::query("VACUUM INTO ?")
                .bind(output.to_string_lossy().as_ref())
                .execute(&pool)
                .await
                .with_context(|| format!("create SQLite backup {}", output.display()))?;
            tracing::info!(path = %output.display(), "SQLite backup complete");
            Ok(())
        }
        Command::Serve {
            listen,
            agent_listen,
            agent_tls_cert,
            agent_tls_key,
            master_key_file,
            web_directory,
        } => {
            let secrets = wiremesh_controller::secrets::SecretBox::from_file(&master_key_file)
                .await
                .with_context(|| format!("load master key from {}", master_key_file.display()))?;
            let tls = match (agent_tls_cert, agent_tls_key) {
                (Some(certificate), Some(key)) => Some((certificate, key)),
                (None, None) => None,
                _ => anyhow::bail!(
                    "WIREMESH_AGENT_TLS_CERT and WIREMESH_AGENT_TLS_KEY must be configured together"
                ),
            };
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("bind controller to {listen}"))?;
            tracing::info!(%listen, "WireMesh controller listening");
            if tls.is_none() {
                tracing::warn!(
                    "agent endpoint disabled because its TLS certificate and private key are not configured"
                );
            }
            let (shutdown_sender, _) = tokio::sync::broadcast::channel::<()>(1);
            let mut tasks = tokio::task::JoinSet::<anyhow::Result<()>>::new();
            let http_shutdown = shutdown_sender.subscribe();
            let http_pool = pool.clone();
            let http_secrets = secrets.clone();
            tasks.spawn(async move {
                let mut shutdown = http_shutdown;
                axum::serve(
                    listener,
                    api::router(AppState {
                        db: http_pool,
                        secrets: http_secrets,
                        web_directory: Some(web_directory),
                    }),
                )
                    .with_graceful_shutdown(async move {
                        let _ = shutdown.recv().await;
                    })
                    .await?;
                Ok(())
            });
            if let Some((certificate, key)) = tls {
                let grpc_pool = pool.clone();
                let grpc_secrets = secrets.clone();
                let grpc_shutdown = shutdown_sender.subscribe();
                tasks.spawn(async move {
                    grpc::serve(
                        grpc_pool,
                        grpc_secrets,
                        agent_listen,
                        &certificate,
                        &key,
                        grpc_shutdown,
                    )
                    .await
                });
            }
            let scheduler_pool = pool.clone();
            let mut scheduler_shutdown = shutdown_sender.subscribe();
            tasks.spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            if let Err(error) = wiremesh_controller::migration::apply_due(&scheduler_pool).await {
                                tracing::error!(%error, "subnet migration scheduler failed");
                            }
                        }
                        _ = scheduler_shutdown.recv() => return Ok(()),
                    }
                }
            });
            let mail_pool = pool.clone();
            let mail_secrets = secrets.clone();
            let mut mail_shutdown = shutdown_sender.subscribe();
            tasks.spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            if let Err(error) = wiremesh_controller::mail::process_one(&mail_pool, &mail_secrets).await {
                                tracing::error!(%error, "mail worker failed");
                            }
                        }
                        _ = mail_shutdown.recv() => return Ok(()),
                    }
                }
            });
            let ldap_pool = pool.clone();
            let ldap_secrets = secrets.clone();
            let mut ldap_shutdown = shutdown_sender.subscribe();
            tasks.spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            if let Err(error) = wiremesh_controller::federated::sync_due_ldap(&ldap_pool, &ldap_secrets).await {
                                tracing::error!(%error, "LDAP synchronization scheduler failed");
                            }
                        }
                        _ = ldap_shutdown.recv() => return Ok(()),
                    }
                }
            });
            tokio::select! {
                () = shutdown_signal() => {
                    tracing::info!("shutdown requested");
                }
                completed = tasks.join_next() => {
                    match completed {
                        Some(Ok(Ok(()))) => tracing::warn!("server task stopped"),
                        Some(Ok(Err(error))) => return Err(error),
                        Some(Err(error)) => return Err(error.into()),
                        None => return Ok(()),
                    }
                }
            }
            let _ = shutdown_sender.send(());
            while let Some(result) = tasks.join_next().await {
                result??;
            }
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
