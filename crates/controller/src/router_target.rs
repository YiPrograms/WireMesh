use sqlx::{Row, SqlitePool};
use url::Url;
use uuid::Uuid;
use wiremesh_agent_core::GatewayCredential;

use crate::{
    desired,
    error::ApiError,
    models::{RouterTargetResponse, UpdateRouterTargetRequest},
    secrets::SecretBox,
    service,
};

fn context(gateway_id: Uuid) -> String {
    format!("router-gateway:{gateway_id}")
}

pub async fn get_for_site(
    pool: &SqlitePool,
    secrets: &SecretBox,
    site_id: Uuid,
) -> Result<RouterTargetResponse, ApiError> {
    let row = sqlx::query(
        "SELECT g.id,g.kind,g.router_url,g.router_credential_envelope
         FROM gateways g WHERE g.site_id=?",
    )
    .bind(site_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("site does not exist".into()))?;
    if row.try_get::<String, _>("kind")? != "mikrotik" {
        return Err(ApiError::Validation(
            "router credentials apply only to MikroTik sites".into(),
        ));
    }
    let gateway_id = parse_uuid(&row.try_get::<String, _>("id")?)?;
    let envelope: Option<Vec<u8>> = row.try_get("router_credential_envelope")?;
    match envelope {
        Some(envelope) => {
            let credential: GatewayCredential = secrets
                .decrypt(&context(gateway_id), &envelope)
                .map_err(|error| ApiError::Internal(error.into()))?;
            Ok(response(true, credential))
        }
        None => Ok(RouterTargetResponse {
            configured: false,
            base_url: row.try_get::<Option<String>, _>("router_url")?.unwrap_or_default(),
            username: String::new(),
            has_password: false,
            has_ca_certificate: false,
        }),
    }
}

pub async fn update_for_site(
    pool: &SqlitePool,
    secrets: &SecretBox,
    actor: Uuid,
    site_id: Uuid,
    request: UpdateRouterTargetRequest,
) -> Result<RouterTargetResponse, ApiError> {
    let row = sqlx::query(
        "SELECT id,kind,router_credential_envelope FROM gateways WHERE site_id=?",
    )
    .bind(site_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("site does not exist".into()))?;
    if row.try_get::<String, _>("kind")? != "mikrotik" {
        return Err(ApiError::Validation(
            "router credentials apply only to MikroTik sites".into(),
        ));
    }
    let gateway_id = parse_uuid(&row.try_get::<String, _>("id")?)?;
    let old = row
        .try_get::<Option<Vec<u8>>, _>("router_credential_envelope")?
        .map(|envelope| {
            secrets
                .decrypt::<GatewayCredential>(&context(gateway_id), &envelope)
                .map_err(|error| ApiError::Internal(error.into()))
        })
        .transpose()?;
    let base_url = validate_url(&request.base_url)?;
    let username = request.username.trim().to_owned();
    if username.is_empty() || username.len() > 128 {
        return Err(ApiError::Validation(
            "RouterOS username must contain 1-128 characters".into(),
        ));
    }
    let password = request
        .password
        .or_else(|| old.as_ref().map(|value| value.password.clone()))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::Validation("RouterOS password is required".into()))?;
    let ca_certificate_pem = request
        .ca_certificate_pem
        .or_else(|| old.as_ref().map(|value| value.ca_certificate_pem.clone()))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::Validation("RouterOS CA certificate is required".into()))?;
    if ca_certificate_pem.len() > 262_144
        || !ca_certificate_pem.contains("-----BEGIN CERTIFICATE-----")
    {
        return Err(ApiError::Validation(
            "RouterOS CA certificate must be a PEM certificate bundle smaller than 256 KiB".into(),
        ));
    }
    let credential = GatewayCredential {
        backend: "mikrotik".into(),
        base_url: base_url.to_string().trim_end_matches('/').to_owned(),
        username,
        password,
        ca_certificate_pem,
    };
    let envelope = secrets
        .encrypt(&context(gateway_id), &credential)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "UPDATE gateways SET router_url=?,router_credential_envelope=?,updated_at=? WHERE id=?",
    )
    .bind(&credential.base_url)
    .bind(envelope)
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(gateway_id.to_string())
    .execute(&mut *transaction)
    .await?;
    desired::rebuild_gateway(&mut transaction, gateway_id, Vec::new()).await?;
    service::audit(
        &mut transaction,
        Some(actor),
        "user",
        "router.credentials.update",
        "gateway",
        Some(gateway_id),
        "success",
        serde_json::json!({"base_url": &credential.base_url, "username": &credential.username}),
    )
    .await?;
    transaction.commit().await?;
    Ok(response(true, credential))
}

pub async fn payload_for_gateway(
    pool: &SqlitePool,
    secrets: &SecretBox,
    gateway_id: Uuid,
) -> Result<Option<Vec<u8>>, ApiError> {
    let row = sqlx::query(
        "SELECT kind,router_credential_envelope FROM gateways WHERE id=?",
    )
    .bind(gateway_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::NotFound("gateway does not exist".into()))?;
    if row.try_get::<String, _>("kind")? != "mikrotik" {
        return Ok(None);
    }
    let Some(envelope) = row.try_get::<Option<Vec<u8>>, _>("router_credential_envelope")? else {
        return Ok(None);
    };
    let credential: GatewayCredential = secrets
        .decrypt(&context(gateway_id), &envelope)
        .map_err(|error| ApiError::Internal(error.into()))?;
    Ok(Some(
        serde_json::to_vec(&credential).map_err(|error| ApiError::Internal(error.into()))?,
    ))
}

fn response(configured: bool, credential: GatewayCredential) -> RouterTargetResponse {
    RouterTargetResponse {
        configured,
        base_url: credential.base_url,
        username: credential.username,
        has_password: !credential.password.is_empty(),
        has_ca_certificate: !credential.ca_certificate_pem.is_empty(),
    }
}

fn validate_url(value: &str) -> Result<Url, ApiError> {
    let url = Url::parse(value.trim())
        .map_err(|_| ApiError::Validation("RouterOS base URL is invalid".into()))?;
    if url.scheme() != "https"
        || !url.has_host()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ApiError::Validation(
            "RouterOS base URL must be an HTTPS origin without credentials, /rest, query, or fragment"
                .into(),
        ));
    }
    Ok(url)
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid gateway UUID: {error}")))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use wiremesh_domain::AclAction;

    use super::*;
    use crate::models::{CreateSiteRequest, GatewayKindRequest};

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
    async fn router_credentials_are_encrypted_and_exported_only_for_the_agent() {
        let pool = pool().await;
        let secrets = SecretBox::from_bytes(&[12_u8; 32]).unwrap();
        let site = service::create_site(
            &pool,
            CreateSiteRequest {
                name: "branch".into(),
                routes: vec!["10.70.0.0/16".parse().unwrap()],
                gateway_kind: GatewayKindRequest::Mikrotik,
                interface_name: "wiremesh".into(),
                endpoint_host: "vpn.example.com".into(),
                public_port: Some(51_820),
                listen_port: Some(51_820),
                public_key: None,
                agent_id: None,
                granted_group_ids: Vec::new(),
                acl_default: AclAction::Allow,
                compatibility_address: false,
            },
        )
        .await
        .unwrap();
        let actor = Uuid::new_v4();
        let result = update_for_site(
            &pool,
            &secrets,
            actor,
            site.id,
            UpdateRouterTargetRequest {
                base_url: "https://router.example.com".into(),
                username: "wiremesh".into(),
                password: Some("router-secret".into()),
                ca_certificate_pem: Some(
                    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".into(),
                ),
            },
        )
        .await
        .unwrap();
        assert!(result.configured && result.has_password && result.has_ca_certificate);
        let envelope: Vec<u8> = sqlx::query_scalar(
            "SELECT router_credential_envelope FROM gateways WHERE id=?",
        )
        .bind(site.gateway_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!String::from_utf8_lossy(&envelope).contains("router-secret"));
        let payload = payload_for_gateway(&pool, &secrets, site.gateway_id)
            .await
            .unwrap()
            .unwrap();
        let credential: GatewayCredential = serde_json::from_slice(&payload).unwrap();
        assert_eq!(credential.password, "router-secret");
    }
}
