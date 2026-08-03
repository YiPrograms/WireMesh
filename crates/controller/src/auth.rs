use std::time::Duration;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, header},
    middleware::Next,
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration as ChronoDuration, Utc};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::{
    AppState,
    error::ApiError,
    models::{AuthUserResponse, BootstrapResult, IssuedTokenResponse},
    secrets::SecretBox,
};

pub const SESSION_COOKIE: &str = "wiremesh_session";
pub const ADMIN_GROUP: &str = "wiremesh-admins";
const MINIMUM_PASSWORD_LENGTH: usize = 12;
const ENROLLMENT_DAYS: i64 = 7;
const SESSION_HOURS: i64 = 12;

#[derive(Debug, Clone)]
pub struct Principal {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub is_admin: bool,
}

impl Principal {
    pub fn response(&self) -> AuthUserResponse {
        AuthUserResponse {
            id: self.id,
            email: self.email.clone(),
            name: self.name.clone(),
            is_admin: self.is_admin,
        }
    }

    pub fn require_admin(&self) -> Result<(), ApiError> {
        if self.is_admin {
            Ok(())
        } else {
            Err(ApiError::Forbidden(
                "administrator access is required".into(),
            ))
        }
    }

    pub fn require_self_or_admin(&self, user_id: Uuid) -> Result<(), ApiError> {
        if self.is_admin || self.id == user_id {
            Ok(())
        } else {
            Err(ApiError::Forbidden(
                "the resource belongs to another user".into(),
            ))
        }
    }
}

pub async fn require_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = session_token(request.headers())
        .ok_or_else(|| ApiError::Unauthorized("sign in is required".into()))?;
    let digest = token_digest(token.as_bytes());
    let row = sqlx::query(
        "SELECT u.id,u.email,u.name,u.manual_disabled,u.ldap_disabled,u.soft_deleted_at
         FROM sessions s JOIN users u ON u.id=s.user_id
         WHERE s.token_hash=? AND s.expires_at > ?",
    )
    .bind(digest.as_slice())
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("session is invalid or expired".into()))?;
    let disabled: bool = row.try_get::<bool, _>("manual_disabled")?
        || row.try_get::<bool, _>("ldap_disabled")?
        || row
            .try_get::<Option<String>, _>("soft_deleted_at")?
            .is_some();
    if disabled {
        return Err(ApiError::Forbidden("user is disabled".into()));
    }
    let id = Uuid::parse_str(&row.try_get::<String, _>("id")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let principal = Principal {
        id,
        email: row.try_get("email")?,
        name: row.try_get("name")?,
        is_admin: is_admin(&state.db, id).await?,
    };
    sqlx::query("UPDATE sessions SET last_seen_at=? WHERE token_hash=?")
        .bind(Utc::now().to_rfc3339())
        .bind(digest.as_slice())
        .execute(&state.db)
        .await?;
    request.extensions_mut().insert(principal);
    Ok(next.run(request).await)
}

pub async fn bootstrap_admin(
    pool: &SqlitePool,
    email: &str,
    name: &str,
) -> Result<BootstrapResult, ApiError> {
    let email = wiremesh_domain::normalize_email(email)?;
    if name.trim().is_empty() {
        return Err(ApiError::Validation("name is required".into()));
    }
    let mut transaction = pool.begin().await?;
    let timestamp = Utc::now().to_rfc3339();
    let user_id = match sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE email=?")
        .bind(&email)
        .fetch_optional(&mut *transaction)
        .await?
    {
        Some(id) => {
            sqlx::query(
                "UPDATE users SET manual_disabled=0,soft_deleted_at=NULL,updated_at=? WHERE id=?",
            )
            .bind(&timestamp)
            .bind(&id)
            .execute(&mut *transaction)
            .await?;
            Uuid::parse_str(&id).map_err(|error| ApiError::Internal(error.into()))?
        }
        None => {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO users(id,email,name,title,creator_kind,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            )
            .bind(id.to_string())
            .bind(&email)
            .bind(name.trim())
            .bind("")
            .bind("local")
            .bind(&timestamp)
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO user_identities(id,user_id,kind,external_id,current_email,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            )
            .bind(Uuid::now_v7().to_string())
            .bind(id.to_string())
            .bind("local")
            .bind(&email)
            .bind(&email)
            .bind(&timestamp)
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
            id
        }
    };
    let group_id =
        match sqlx::query_scalar::<_, String>("SELECT id FROM groups WHERE normalized_name=?")
            .bind(ADMIN_GROUP)
            .fetch_optional(&mut *transaction)
            .await?
        {
            Some(id) => id,
            None => {
                let id = Uuid::now_v7().to_string();
                sqlx::query(
                "INSERT INTO groups(id,normalized_name,display_name,created_at) VALUES(?,?,?,?)",
            )
            .bind(&id)
            .bind(ADMIN_GROUP)
            .bind("WireMesh Administrators")
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
                id
            }
        };
    sqlx::query(
        "INSERT INTO group_memberships(id,group_id,user_id,source_kind,source_id,active,updated_at)
         VALUES(?,?,?,?,?,1,?)
         ON CONFLICT(group_id,user_id,source_kind,source_id) DO UPDATE SET active=1,updated_at=excluded.updated_at",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(group_id)
    .bind(user_id.to_string())
    .bind("local")
    .bind("bootstrap")
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;

    let token = random_token();
    let expires_at = (Utc::now() + ChronoDuration::days(ENROLLMENT_DAYS)).to_rfc3339();
    sqlx::query(
        "UPDATE one_time_tokens SET consumed_at=? WHERE user_id=? AND purpose='enrollment' AND consumed_at IS NULL",
    )
    .bind(&timestamp)
    .bind(user_id.to_string())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO one_time_tokens(id,user_id,purpose,token_hash,expires_at,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(user_id.to_string())
    .bind("enrollment")
    .bind(token_digest(token.as_bytes()).as_slice())
    .bind(&expires_at)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        Some(user_id),
        "bootstrap",
        "admin.bootstrap",
        "user",
        Some(user_id),
    )
    .await?;
    transaction.commit().await?;
    Ok(BootstrapResult {
        user_id,
        enrollment_token: token,
        expires_at,
    })
}

/// Bootstrap the requested administrator only when the installation has no
/// enabled administrator. This makes container first-start initialization
/// idempotent without replacing enrollment tokens on every restart.
pub async fn bootstrap_admin_if_needed(
    pool: &SqlitePool,
    email: &str,
    name: &str,
) -> Result<Option<BootstrapResult>, ApiError> {
    let enabled_administrators: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT u.id) FROM users u
         JOIN effective_group_memberships gm ON gm.user_id=u.id
         JOIN groups g ON g.id=gm.group_id AND g.normalized_name=?
         WHERE u.manual_disabled=0 AND u.ldap_disabled=0 AND u.soft_deleted_at IS NULL",
    )
    .bind(ADMIN_GROUP)
    .fetch_one(pool)
    .await?;
    if enabled_administrators > 0 {
        return Ok(None);
    }
    bootstrap_admin(pool, email, name).await.map(Some)
}

pub async fn issue_enrollment_token(
    pool: &SqlitePool,
    secrets: &SecretBox,
    actor: Uuid,
    user_id: Uuid,
) -> Result<IssuedTokenResponse, ApiError> {
    issue_user_token(
        pool,
        secrets,
        actor,
        user_id,
        "enrollment",
        ENROLLMENT_DAYS * 24,
    )
    .await
}

pub async fn issue_reset_token(
    pool: &SqlitePool,
    secrets: &SecretBox,
    actor: Uuid,
    user_id: Uuid,
) -> Result<IssuedTokenResponse, ApiError> {
    issue_user_token(pool, secrets, actor, user_id, "reset", 1).await
}

async fn issue_user_token(
    pool: &SqlitePool,
    secrets: &SecretBox,
    actor: Uuid,
    user_id: Uuid,
    purpose: &str,
    lifetime_hours: i64,
) -> Result<IssuedTokenResponse, ApiError> {
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT email,manual_disabled,ldap_disabled,soft_deleted_at,purged_at FROM users WHERE id=?",
    )
    .bind(user_id.to_string())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::NotFound("user does not exist".into()))?;
    ensure_row_enabled(&row)?;
    if row.try_get::<Option<String>, _>("purged_at")?.is_some() {
        return Err(ApiError::Conflict(
            "purged users cannot receive tokens".into(),
        ));
    }
    let email: String = row.try_get("email")?;
    if purpose == "reset" {
        let has_password: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM local_passwords WHERE user_id=?")
                .bind(user_id.to_string())
                .fetch_one(&mut *transaction)
                .await?;
        if has_password == 0 {
            return Err(ApiError::Conflict(
                "user has no local password; issue an enrollment token instead".into(),
            ));
        }
    }
    let timestamp = Utc::now();
    let expires_at = (timestamp + ChronoDuration::hours(lifetime_hours)).to_rfc3339();
    let token = random_token();
    let token_id = Uuid::now_v7();
    sqlx::query(
        "UPDATE one_time_tokens SET consumed_at=? WHERE user_id=? AND purpose=? AND consumed_at IS NULL",
    )
    .bind(timestamp.to_rfc3339())
    .bind(user_id.to_string())
    .bind(purpose)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO one_time_tokens(id,user_id,purpose,token_hash,expires_at,created_at)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(token_id.to_string())
    .bind(user_id.to_string())
    .bind(purpose)
    .bind(token_digest(token.as_bytes()))
    .bind(&expires_at)
    .bind(timestamp.to_rfc3339())
    .execute(&mut *transaction)
    .await?;
    if purpose == "enrollment" {
        let has_local: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_identities WHERE user_id=? AND kind='local'",
        )
        .bind(user_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        if has_local == 0 {
            sqlx::query(
                "INSERT INTO user_identities(id,user_id,kind,external_id,current_email,created_at,updated_at)
                 VALUES(?,?,?,?,?,?,?)",
            )
            .bind(Uuid::now_v7().to_string())
            .bind(user_id.to_string())
            .bind("local")
            .bind(&email)
            .bind(&email)
            .bind(timestamp.to_rfc3339())
            .bind(timestamp.to_rfc3339())
            .execute(&mut *transaction)
            .await?;
        }
    }
    let job_id = Uuid::now_v7();
    #[derive(Serialize)]
    struct MailToken<'a> {
        token: &'a str,
    }
    let envelope = secrets
        .encrypt(&format!("mail-job:{job_id}"), &MailToken { token: &token })
        .map_err(|error| ApiError::Internal(error.into()))?;
    // A newly issued token supersedes earlier links. Keep the delivery history,
    // but erase recoverable payloads for queued jobs that can no longer work.
    sqlx::query(
        "UPDATE mail_jobs
         SET status='failed',secret_envelope=NULL,last_error='superseded by a newer token'
         WHERE recipient=? AND template=? AND status='pending'",
    )
    .bind(&email)
    .bind(purpose)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO mail_jobs(id,recipient,template,parameters_json,secret_envelope,next_attempt_at,created_at)
         VALUES(?,?,?,?,?,?,?)",
    )
    .bind(job_id.to_string())
    .bind(email)
    .bind(purpose)
    .bind(serde_json::json!({"user_id": user_id, "token_id": token_id}).to_string())
    .bind(envelope)
    .bind(timestamp.to_rfc3339())
    .bind(timestamp.to_rfc3339())
    .execute(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        Some(actor),
        "user",
        if purpose == "reset" {
            "auth.reset.issue"
        } else {
            "auth.enrollment.issue"
        },
        "user",
        Some(user_id),
    )
    .await?;
    transaction.commit().await?;
    Ok(IssuedTokenResponse {
        user_id,
        purpose: purpose.into(),
        token,
        expires_at,
    })
}

pub async fn enroll(
    pool: &SqlitePool,
    token: &str,
    password: &str,
) -> Result<(Principal, String), ApiError> {
    consume_password_token(pool, token, password, "enrollment", "auth.enroll").await
}

pub async fn reset_password(
    pool: &SqlitePool,
    token: &str,
    password: &str,
) -> Result<(Principal, String), ApiError> {
    consume_password_token(pool, token, password, "reset", "auth.reset").await
}

async fn consume_password_token(
    pool: &SqlitePool,
    token: &str,
    password: &str,
    purpose: &str,
    audit_action: &str,
) -> Result<(Principal, String), ApiError> {
    validate_password(password)?;
    let digest = token_digest(token.as_bytes());
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT t.id,t.user_id,u.email,u.name,u.manual_disabled,u.ldap_disabled,u.soft_deleted_at
         FROM one_time_tokens t JOIN users u ON u.id=t.user_id
         WHERE t.token_hash=? AND t.purpose=? AND t.consumed_at IS NULL AND t.expires_at>?",
    )
    .bind(digest.as_slice())
    .bind(purpose)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::Unauthorized(format!("{purpose} token is invalid or expired")))?;
    ensure_row_enabled(&row)?;
    let user_id = Uuid::parse_str(&row.try_get::<String, _>("user_id")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let hash = hash_password(password)?;
    let timestamp = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO local_passwords(user_id,password_hash,updated_at) VALUES(?,?,?)
         ON CONFLICT(user_id) DO UPDATE SET password_hash=excluded.password_hash,updated_at=excluded.updated_at",
    )
    .bind(user_id.to_string())
    .bind(hash)
    .bind(&timestamp)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE one_time_tokens SET consumed_at=? WHERE id=?")
        .bind(&timestamp)
        .bind(row.try_get::<String, _>("id")?)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE mail_jobs
         SET status='failed',secret_envelope=NULL,last_error='token already consumed'
         WHERE template=? AND status='pending'
           AND json_extract(parameters_json,'$.token_id')=?",
    )
    .bind(purpose)
    .bind(row.try_get::<String, _>("id")?)
    .execute(&mut *transaction)
    .await?;
    if purpose == "reset" {
        sqlx::query("DELETE FROM sessions WHERE user_id=?")
            .bind(user_id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    let (session_token, _) = create_session(&mut transaction, user_id).await?;
    insert_audit(
        &mut transaction,
        Some(user_id),
        "user",
        audit_action,
        "session",
        None,
    )
    .await?;
    transaction.commit().await?;
    let principal = Principal {
        id: user_id,
        email: row.try_get("email")?,
        name: row.try_get("name")?,
        is_admin: is_admin(pool, user_id).await?,
    };
    Ok((principal, session_token))
}

pub async fn login_local(
    pool: &SqlitePool,
    email: &str,
    password: &str,
) -> Result<(Principal, String), ApiError> {
    let email = wiremesh_domain::normalize_email(email)?;
    let row = sqlx::query(
        "SELECT u.id,u.email,u.name,u.manual_disabled,u.ldap_disabled,u.soft_deleted_at,p.password_hash
         FROM users u JOIN local_passwords p ON p.user_id=u.id WHERE u.email=?",
    )
    .bind(&email)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("email or password is incorrect".into()))?;
    ensure_row_enabled(&row)?;
    let password_hash: String = row.try_get("password_hash")?;
    let parsed = PasswordHash::new(&password_hash)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
    argon2()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| ApiError::Unauthorized("email or password is incorrect".into()))?;
    let user_id = Uuid::parse_str(&row.try_get::<String, _>("id")?)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let mut transaction = pool.begin().await?;
    let (session_token, _) = create_session(&mut transaction, user_id).await?;
    insert_audit(
        &mut transaction,
        Some(user_id),
        "user",
        "auth.login.local",
        "session",
        None,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        Principal {
            id: user_id,
            email: row.try_get("email")?,
            name: row.try_get("name")?,
            is_admin: is_admin(pool, user_id).await?,
        },
        session_token,
    ))
}

pub async fn logout(pool: &SqlitePool, headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(token) = session_token(headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash=?")
            .bind(token_digest(token.as_bytes()).as_slice())
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn record_auth_failure(pool: &SqlitePool, action: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_events(id,occurred_at,actor_kind,action,object_kind,outcome,details_json)
         VALUES(?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(Utc::now().to_rfc3339())
    .bind("anonymous")
    .bind(action)
    .bind("session")
    .bind("failure")
    .bind("{}")
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn establish_session(
    pool: &SqlitePool,
    user_id: Uuid,
    audit_action: &str,
) -> Result<(Principal, String), ApiError> {
    let row = sqlx::query(
        "SELECT id,email,name,manual_disabled,ldap_disabled,soft_deleted_at FROM users WHERE id=?",
    )
    .bind(user_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("linked user does not exist".into()))?;
    ensure_row_enabled(&row)?;
    let mut transaction = pool.begin().await?;
    let (token, _) = create_session(&mut transaction, user_id).await?;
    insert_audit(
        &mut transaction,
        Some(user_id),
        "user",
        audit_action,
        "session",
        None,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        Principal {
            id: user_id,
            email: row.try_get("email")?,
            name: row.try_get("name")?,
            is_admin: is_admin(pool, user_id).await?,
        },
        token,
    ))
}

pub fn session_cookie(token: &str) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        Duration::from_secs((SESSION_HOURS * 3600) as u64).as_secs()
    ))
    .map_err(|error| ApiError::Internal(error.into()))
}

pub fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "wiremesh_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    )
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        return Some(token);
    }
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|part| {
                let (name, value) = part.trim().split_once('=')?;
                (name == SESSION_COOKIE).then_some(value)
            })
        })
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < MINIMUM_PASSWORD_LENGTH {
        Err(ApiError::Validation(format!(
            "password must contain at least {MINIMUM_PASSWORD_LENGTH} characters"
        )))
    } else if password.as_bytes().len() > 1024 {
        Err(ApiError::Validation("password is too long".into()))
    } else {
        Ok(())
    }
}

fn argon2() -> Argon2<'static> {
    let params = Params::new(65_536, 3, 1, None).expect("Argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn random_secret() -> String {
    random_token()
}

pub fn token_digest(token: &[u8]) -> Vec<u8> {
    Sha256::digest(token).to_vec()
}

async fn create_session(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: Uuid,
) -> Result<(String, String), ApiError> {
    let token = random_token();
    let timestamp = Utc::now();
    let expires_at = (timestamp + ChronoDuration::hours(SESSION_HOURS)).to_rfc3339();
    sqlx::query(
        "INSERT INTO sessions(id,user_id,token_hash,expires_at,last_seen_at,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(user_id.to_string())
    .bind(token_digest(token.as_bytes()).as_slice())
    .bind(&expires_at)
    .bind(timestamp.to_rfc3339())
    .bind(timestamp.to_rfc3339())
    .execute(&mut **transaction)
    .await?;
    Ok((token, expires_at))
}

async fn is_admin(pool: &SqlitePool, user_id: Uuid) -> Result<bool, ApiError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM effective_group_memberships gm JOIN groups g ON g.id=gm.group_id
         WHERE gm.user_id=? AND g.normalized_name=?",
    )
    .bind(user_id.to_string())
    .bind(ADMIN_GROUP)
    .fetch_one(pool)
    .await?
        > 0)
}

fn ensure_row_enabled(row: &sqlx::sqlite::SqliteRow) -> Result<(), ApiError> {
    let disabled = row.try_get::<bool, _>("manual_disabled")?
        || row.try_get::<bool, _>("ldap_disabled")?
        || row
            .try_get::<Option<String>, _>("soft_deleted_at")?
            .is_some();
    if disabled {
        Err(ApiError::Forbidden("user is disabled".into()))
    } else {
        Ok(())
    }
}

async fn insert_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    actor_user_id: Option<Uuid>,
    actor_kind: &str,
    action: &str,
    object_kind: &str,
    object_id: Option<Uuid>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_events(id,occurred_at,actor_user_id,actor_kind,action,object_kind,object_id,outcome,details_json) VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(Utc::now().to_rfc3339())
    .bind(actor_user_id.map(|value| value.to_string()))
    .bind(actor_kind)
    .bind(action)
    .bind(object_kind)
    .bind(object_id.map(|value| value.to_string()))
    .bind("success")
    .bind("{}")
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    async fn pool() -> SqlitePool {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn enrollment_is_single_use_and_argon2_parameters_are_fixed() {
        let pool = pool().await;
        let bootstrap = bootstrap_admin(&pool, "Admin@Example.com", "Admin")
            .await
            .unwrap();
        let (principal, token) = enroll(
            &pool,
            &bootstrap.enrollment_token,
            "a sufficiently long password",
        )
        .await
        .unwrap();
        assert!(principal.is_admin);
        assert!(!token.is_empty());
        assert!(
            enroll(&pool, &bootstrap.enrollment_token, "another long password")
                .await
                .is_err()
        );
        let hash: String = sqlx::query_scalar("SELECT password_hash FROM local_passwords")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(hash.contains("m=65536,t=3,p=1"));
        assert!(
            login_local(&pool, "admin@example.com", "a sufficiently long password")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn automatic_bootstrap_only_runs_without_an_enabled_admin() {
        let pool = pool().await;
        let first = bootstrap_admin_if_needed(&pool, "admin@example.com", "Admin")
            .await
            .unwrap();
        assert!(first.is_some());
        let second = bootstrap_admin_if_needed(&pool, "other@example.com", "Other")
            .await
            .unwrap();
        assert!(second.is_none());
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users, 1);
    }
}
