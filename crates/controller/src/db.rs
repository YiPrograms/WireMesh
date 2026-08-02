use std::{path::Path, str::FromStr};

use anyhow::Context;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

pub async fn connect(database_url: &str) -> anyhow::Result<SqlitePool> {
    if let Some(path) = sqlite_file_path(database_url)
        && let Some(parent) = path.parent()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create SQLite directory {}", parent.display()))?;
    }

    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

fn sqlite_file_path(database_url: &str) -> Option<&Path> {
    let raw = database_url.strip_prefix("sqlite://")?;
    let without_query = raw.split('?').next().unwrap_or(raw);
    if without_query == ":memory:" || without_query.is_empty() {
        None
    } else {
        Some(Path::new(without_query))
    }
}

pub async fn ready(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(pool)
        .await?;
    Ok(())
}
