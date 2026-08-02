use chrono::Utc;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{SmtpSecurity, SmtpSettingsResponse, UpdateSmtpSettingsRequest},
    secrets::SecretBox,
};

const SECRET_CONTEXT: &str = "smtp-settings:1";
const MAX_ATTEMPTS: i64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSmtpConfig {
    host: String,
    port: u16,
    security: SmtpSecurity,
    username: Option<String>,
    password: Option<String>,
    from_address: String,
    public_base_url: String,
}

pub async fn get_settings(
    pool: &SqlitePool,
    secrets: &SecretBox,
) -> Result<SmtpSettingsResponse, ApiError> {
    let row = sqlx::query("SELECT enabled,config_envelope FROM smtp_settings WHERE singleton=1")
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(SmtpSettingsResponse {
            configured: false,
            enabled: false,
            host: String::new(),
            port: 587,
            security: SmtpSecurity::StartTls,
            username: None,
            has_password: false,
            from_address: String::new(),
            public_base_url: String::new(),
        });
    };
    let config: StoredSmtpConfig = secrets
        .decrypt(SECRET_CONTEXT, &row.try_get::<Vec<u8>, _>("config_envelope")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    Ok(response(row.try_get("enabled")?, config))
}

pub async fn update_settings(
    pool: &SqlitePool,
    secrets: &SecretBox,
    actor: Uuid,
    request: UpdateSmtpSettingsRequest,
) -> Result<SmtpSettingsResponse, ApiError> {
    let host = request.host.trim().to_owned();
    if host.is_empty() || request.port == 0 {
        return Err(ApiError::Validation("SMTP host and port are required".into()));
    }
    let _: Mailbox = request
        .from_address
        .parse()
        .map_err(|_| ApiError::Validation("SMTP sender address is invalid".into()))?;
    let base_url = url::Url::parse(request.public_base_url.trim())
        .map_err(|_| ApiError::Validation("public base URL is invalid".into()))?;
    if !matches!(base_url.scheme(), "http" | "https") {
        return Err(ApiError::Validation(
            "public base URL must use HTTP or HTTPS".into(),
        ));
    }
    let old_password = match sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT config_envelope FROM smtp_settings WHERE singleton=1",
    )
    .fetch_optional(pool)
    .await?
    {
        Some(envelope) => secrets
            .decrypt::<StoredSmtpConfig>(SECRET_CONTEXT, &envelope)
            .map_err(|error| ApiError::Internal(error.into()))?
            .password,
        None => None,
    };
    let password = match request.password {
        Some(value) if value.is_empty() => None,
        Some(value) => Some(value),
        None => old_password,
    };
    if request.username.as_deref().is_some_and(str::is_empty) {
        return Err(ApiError::Validation("SMTP username cannot be empty".into()));
    }
    if request.enabled && request.username.is_some() != password.is_some() {
        return Err(ApiError::Validation(
            "SMTP username and password must be configured together".into(),
        ));
    }
    let config = StoredSmtpConfig {
        host,
        port: request.port,
        security: request.security,
        username: request.username,
        password,
        from_address: request.from_address.trim().to_owned(),
        public_base_url: base_url.as_str().trim_end_matches('/').to_owned(),
    };
    let envelope = secrets
        .encrypt(SECRET_CONTEXT, &config)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let timestamp = Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO smtp_settings(singleton,enabled,config_envelope,updated_at) VALUES(1,?,?,?)
         ON CONFLICT(singleton) DO UPDATE SET enabled=excluded.enabled,config_envelope=excluded.config_envelope,updated_at=excluded.updated_at",
    )
    .bind(request.enabled)
    .bind(envelope)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO audit_events(id,occurred_at,actor_user_id,actor_kind,action,object_kind,object_id,outcome,details_json)
         VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(&timestamp)
    .bind(actor.to_string())
    .bind("user")
    .bind("smtp.settings.update")
    .bind("smtp_settings")
    .bind("1")
    .bind("success")
    .bind(serde_json::json!({"enabled": request.enabled, "host": config.host}).to_string())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(response(request.enabled, config))
}

pub async fn process_one(pool: &SqlitePool, secrets: &SecretBox) -> Result<bool, ApiError> {
    let timestamp = Utc::now();
    // Token verification stores only a digest. The separately encrypted copy
    // needed for durable delivery is erased as soon as its token is unusable,
    // including while SMTP is disabled.
    sqlx::query(
        "UPDATE mail_jobs
         SET status='failed',secret_envelope=NULL,last_error='token expired or consumed'
         WHERE status='pending' AND template IN ('enrollment','reset')
           AND EXISTS(
             SELECT 1 FROM one_time_tokens token
             WHERE token.id=json_extract(mail_jobs.parameters_json,'$.token_id')
               AND (token.consumed_at IS NOT NULL OR token.expires_at<=?)
           )",
    )
    .bind(timestamp.to_rfc3339())
    .execute(pool)
    .await?;
    let settings = sqlx::query("SELECT enabled,config_envelope FROM smtp_settings WHERE singleton=1")
        .fetch_optional(pool)
        .await?;
    let Some(settings) = settings else { return Ok(false); };
    if !settings.try_get::<bool, _>("enabled")? {
        return Ok(false);
    }
    let config: StoredSmtpConfig = secrets
        .decrypt(SECRET_CONTEXT, &settings.try_get::<Vec<u8>, _>("config_envelope")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    sqlx::query(
        "UPDATE mail_jobs SET status='pending',claimed_at=NULL
         WHERE status='sending'
           AND (claimed_at IS NULL OR claimed_at<=?)",
    )
    .bind((timestamp - chrono::Duration::minutes(5)).to_rfc3339())
    .execute(pool)
    .await?;
    let row = sqlx::query(
        "UPDATE mail_jobs SET status='sending',attempts=attempts+1,claimed_at=?
         WHERE id=(SELECT id FROM mail_jobs WHERE status='pending' AND next_attempt_at<=? ORDER BY created_at LIMIT 1)
         RETURNING id,recipient,template,parameters_json,secret_envelope,attempts",
    )
    .bind(timestamp.to_rfc3339())
    .bind(timestamp.to_rfc3339())
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else { return Ok(false); };
    let id: String = row.try_get("id")?;
    let attempts: i64 = row.try_get("attempts")?;
    let mut parameters: serde_json::Value =
        serde_json::from_str(&row.try_get::<String, _>("parameters_json")?)
            .map_err(|error| ApiError::Internal(error.into()))?;
    if let Some(envelope) = row.try_get::<Option<Vec<u8>>, _>("secret_envelope")? {
        let secret: serde_json::Value = secrets
            .decrypt(&format!("mail-job:{id}"), &envelope)
            .map_err(|error| ApiError::Internal(error.into()))?;
        if let (Some(parameters), Some(secret)) = (parameters.as_object_mut(), secret.as_object()) {
            parameters.extend(secret.clone());
        }
    }
    let result = send_job(
        &config,
        &row.try_get::<String, _>("recipient")?,
        &row.try_get::<String, _>("template")?,
        &parameters,
    )
    .await;
    match result {
        Ok(()) => {
            sqlx::query("UPDATE mail_jobs SET status='sent',sent_at=?,last_error=NULL,claimed_at=NULL,secret_envelope=NULL WHERE id=?")
                .bind(Utc::now().to_rfc3339())
                .bind(id)
                .execute(pool)
                .await?;
        }
        Err(error) => {
            let failed = attempts >= MAX_ATTEMPTS;
            let delay_minutes = 2_i64.pow((attempts.min(8) - 1).max(0) as u32);
            sqlx::query(
                "UPDATE mail_jobs SET status=?,next_attempt_at=?,last_error=?,claimed_at=NULL,
                                      secret_envelope=CASE WHEN ? THEN NULL ELSE secret_envelope END
                 WHERE id=?",
            )
            .bind(if failed { "failed" } else { "pending" })
            .bind((Utc::now() + chrono::Duration::minutes(delay_minutes)).to_rfc3339())
            .bind(truncate_error(&error.to_string()))
            .bind(failed)
            .bind(id)
            .execute(pool)
            .await?;
            tracing::warn!(%error, attempts, "SMTP delivery failed");
        }
    }
    Ok(true)
}

async fn send_job(
    config: &StoredSmtpConfig,
    recipient: &str,
    template: &str,
    parameters: &serde_json::Value,
) -> anyhow::Result<()> {
    let (subject, body) = render(template, parameters, &config.public_base_url);
    let message = Message::builder()
        .from(config.from_address.parse()?)
        .to(recipient.parse()?)
        .subject(subject)
        .body(body)?;
    let mut builder = match config.security {
        SmtpSecurity::StartTls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)?
        }
        SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?,
    }
    .port(config.port);
    if let (Some(username), Some(password)) = (&config.username, &config.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }
    builder.build().send(message).await?;
    Ok(())
}

fn render(template: &str, parameters: &serde_json::Value, base_url: &str) -> (String, String) {
    match template {
        "pool_migration" => (
            "WireMesh VPN address migration scheduled".into(),
            format!(
                "Your WireMesh VPN address will change at {}. After that time, sign in at {} to download or update your profile.\n\nNo private key or complete profile is included in this email.\n",
                parameters.get("effective_at").and_then(|value| value.as_str()).unwrap_or("the scheduled time"),
                base_url,
            ),
        ),
        "enrollment" => (
            "Complete your WireMesh enrollment".into(),
            format!(
                "Open {base_url}/?enrollment={} to complete enrollment. This link expires in seven days and works once.\n",
                parameters.get("token").and_then(|value| value.as_str()).unwrap_or_default(),
            ),
        ),
        "reset" => (
            "Reset your WireMesh account".into(),
            format!(
                "Open {base_url}/?reset={} to choose a new password. This link expires in one hour and works once.\n",
                parameters.get("token").and_then(|value| value.as_str()).unwrap_or_default(),
            ),
        ),
        "access_change" => (
            "Your WireMesh access changed".into(),
            format!("Your VPN access changed. Review it at {base_url}.\n"),
        ),
        "profile_change" => (
            "Your WireMesh profile changed".into(),
            format!("Your VPN profile changed. Review it at {base_url}.\n"),
        ),
        _ => (
            "WireMesh notification".into(),
            format!("A WireMesh account event is available at {base_url}.\n"),
        ),
    }
}

fn response(enabled: bool, config: StoredSmtpConfig) -> SmtpSettingsResponse {
    SmtpSettingsResponse {
        configured: true,
        enabled,
        host: config.host,
        port: config.port,
        security: config.security,
        username: config.username,
        has_password: config.password.is_some(),
        from_address: config.from_address,
        public_base_url: config.public_base_url,
    }
}

fn truncate_error(value: &str) -> String {
    value.chars().take(500).collect()
}
