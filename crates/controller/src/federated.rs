use std::{collections::{BTreeSet, HashMap}, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry,
    adapters::{Adapter, EntriesOnly, PagedResults},
    ldap_escape,
};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope as OidcScope,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::{
    auth::{self, Principal},
    error::ApiError,
    identity,
    models::{LdapLoginRequest, LoginProviderResponse, OidcClaims, ProviderKind},
    secrets::SecretBox,
};

#[derive(Debug, Deserialize)]
struct LdapConfig {
    url: String,
    #[serde(default)]
    start_tls: bool,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
    #[serde(default = "default_user_filter")]
    user_filter: String,
    #[serde(default = "default_id_attribute")]
    id_attribute: String,
    #[serde(default = "default_email_attribute")]
    email_attribute: String,
    #[serde(default = "default_name_attribute")]
    name_attribute: String,
    #[serde(default = "default_title_attribute")]
    title_attribute: String,
    #[serde(default = "default_group_attribute")]
    group_attribute: String,
    group_base_dn: Option<String>,
    #[serde(default = "default_group_filter")]
    group_filter: String,
    #[serde(default = "default_group_name_attribute")]
    group_name_attribute: String,
    #[serde(default = "default_group_member_attribute")]
    group_member_attribute: String,
    #[serde(default)]
    nested_group_depth: u8,
    disabled_attribute: Option<String>,
    #[serde(default)]
    disabled_values: Vec<String>,
    #[serde(default = "default_page_size")]
    page_size: u32,
}

#[derive(Debug, Deserialize)]
struct OidcConfig {
    issuer_url: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    #[serde(default)]
    scopes: Vec<String>,
    userinfo_url: Option<String>,
    #[serde(default = "default_groups_claim")]
    groups_claim: String,
    #[serde(default = "default_title_claim")]
    title_claim: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OidcStateSecret {
    verifier: String,
    nonce: String,
}

fn default_user_filter() -> String { "(objectClass=person)".into() }
fn default_id_attribute() -> String { "entryUUID".into() }
fn default_email_attribute() -> String { "mail".into() }
fn default_name_attribute() -> String { "displayName".into() }
fn default_title_attribute() -> String { "title".into() }
fn default_group_attribute() -> String { "memberOf".into() }
fn default_group_filter() -> String { "(objectClass=groupOfNames)".into() }
fn default_group_name_attribute() -> String { "cn".into() }
fn default_group_member_attribute() -> String { "member".into() }
fn default_page_size() -> u32 { 500 }
fn default_groups_claim() -> String { "groups".into() }
fn default_title_claim() -> String { "title".into() }

pub async fn login_providers(pool: &SqlitePool) -> Result<Vec<LoginProviderResponse>, ApiError> {
    let rows = sqlx::query("SELECT id,kind,name FROM identity_providers WHERE enabled=1 ORDER BY priority,name")
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(LoginProviderResponse {
                id: parse_uuid(&row.try_get::<String, _>("id")?)?,
                kind: parse_kind(&row.try_get::<String, _>("kind")?)?,
                name: row.try_get("name")?,
            })
        })
        .collect()
}

pub async fn login_ldap(
    pool: &SqlitePool,
    secrets: &SecretBox,
    request: LdapLoginRequest,
) -> Result<(Principal, String), ApiError> {
    if request.password.is_empty() {
        return Err(ApiError::Unauthorized("email or password is incorrect".into()));
    }
    let email = wiremesh_domain::normalize_email(&request.email)?;
    let provider = identity::get_provider(pool, request.provider_id).await?;
    if !provider.enabled || !matches!(provider.kind, ProviderKind::Ldap) {
        return Err(ApiError::Forbidden("LDAP realm is not enabled".into()));
    }
    let config: LdapConfig = secrets
        .decrypt(
            &format!("identity-provider:{}", request.provider_id),
            &sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT config_envelope FROM identity_providers WHERE id=?",
            )
            .bind(request.provider_id.to_string())
            .fetch_one(pool)
            .await?,
        )
        .map_err(|error| ApiError::Internal(error.into()))?;
    let settings = LdapConnSettings::new()
        .set_starttls(config.start_tls)
        .set_conn_timeout(Duration::from_secs(10));
    let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &config.url)
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("connect to LDAP: {error}")))?;
    ldap3::drive!(connection);
    ldap.simple_bind(&config.bind_dn, &config.bind_password)
        .await
        .and_then(ldap3::result::LdapResult::success)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("LDAP service bind failed: {error}")))?;
    let escaped = ldap_escape(&email);
    let filter = format!(
        "(&{}({}={}))",
        config.user_filter, config.email_attribute, escaped
    );
    let (entries, _) = ldap
        .search(
            &config.base_dn,
            Scope::Subtree,
            &filter,
            vec![config.id_attribute.as_str(), config.email_attribute.as_str()],
        )
        .await
        .and_then(ldap3::result::SearchResult::success)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("LDAP lookup failed: {error}")))?;
    if entries.len() != 1 {
        let _ = ldap.unbind().await;
        return Err(ApiError::Unauthorized("email or password is incorrect".into()));
    }
    let entry = SearchEntry::construct(entries.into_iter().next().expect("one LDAP result"));
    let external_id = entry
        .attrs
        .get(&config.id_attribute)
        .and_then(|values| values.first())
        .cloned()
        .ok_or_else(|| ApiError::Forbidden("LDAP entry has no immutable identifier".into()))?;
    ldap.simple_bind(&entry.dn, &request.password)
        .await
        .and_then(ldap3::result::LdapResult::success)
        .map_err(|_| ApiError::Unauthorized("email or password is incorrect".into()))?;
    let _ = ldap.unbind().await;
    let user_id: String = sqlx::query_scalar(
        "SELECT ui.user_id FROM user_identities ui JOIN users u ON u.id=ui.user_id
         WHERE ui.provider_id=? AND ui.external_id=? AND ui.kind='ldap' AND ui.active=1 AND ui.provider_enabled=1
           AND u.manual_disabled=0 AND u.ldap_disabled=0 AND u.soft_deleted_at IS NULL",
    )
    .bind(request.provider_id.to_string())
    .bind(external_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::Forbidden("LDAP identity is not active in the latest full sync".into()))?;
    auth::establish_session(pool, parse_uuid(&user_id)?, "auth.login.ldap").await
}

pub async fn sync_ldap_provider(
    pool: &SqlitePool,
    secrets: &SecretBox,
    provider_id: Uuid,
) -> Result<usize, ApiError> {
    let provider = identity::get_provider(pool, provider_id).await?;
    if !provider.enabled || !matches!(provider.kind, ProviderKind::Ldap) {
        return Err(ApiError::Validation("provider is not an enabled LDAP realm".into()));
    }
    let config: LdapConfig = secrets
        .decrypt(
            &format!("identity-provider:{provider_id}"),
            &sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT config_envelope FROM identity_providers WHERE id=?",
            )
            .bind(provider_id.to_string())
            .fetch_one(pool)
            .await?,
        )
        .map_err(|error| ApiError::Internal(error.into()))?;
    if config.page_size == 0 || config.page_size > 5_000 {
        return Err(ApiError::Validation("LDAP page_size must be between 1 and 5000".into()));
    }
    if config.nested_group_depth > 32 {
        return Err(ApiError::Validation("LDAP nested_group_depth cannot exceed 32".into()));
    }
    let settings = LdapConnSettings::new()
        .set_starttls(config.start_tls)
        .set_conn_timeout(Duration::from_secs(10));
    let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &config.url)
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("connect to LDAP: {error}")))?;
    ldap3::drive!(connection);
    ldap.simple_bind(&config.bind_dn, &config.bind_password)
        .await
        .and_then(ldap3::result::LdapResult::success)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("LDAP service bind failed: {error}")))?;

    let groups = if let Some(base) = &config.group_base_dn {
        paged_search(
            &mut ldap,
            config.page_size,
            base,
            &config.group_filter,
            vec![
                config.group_name_attribute.as_str(),
                config.group_member_attribute.as_str(),
            ],
        )
        .await?
    } else {
        Vec::new()
    };
    let group_graph = build_group_graph(&config, groups);
    let mut attributes = vec![
        config.id_attribute.as_str(),
        config.email_attribute.as_str(),
        config.name_attribute.as_str(),
        config.title_attribute.as_str(),
        config.group_attribute.as_str(),
    ];
    if let Some(attribute) = &config.disabled_attribute {
        attributes.push(attribute);
    }
    let users = paged_search(
        &mut ldap,
        config.page_size,
        &config.base_dn,
        &config.user_filter,
        attributes,
    )
    .await?;
    let _ = ldap.unbind().await;
    let mut entries = Vec::with_capacity(users.len());
    for user in users {
        let external_id = attribute_or_binary(&user, &config.id_attribute)
            .ok_or_else(|| ApiError::Validation(format!("LDAP entry {} has no immutable ID", user.dn)))?;
        let email = first_attribute(&user, &config.email_attribute)
            .ok_or_else(|| ApiError::Validation(format!("LDAP entry {} has no email", user.dn)))?;
        let name = first_attribute(&user, &config.name_attribute).unwrap_or_else(|| email.clone());
        let title = first_attribute(&user, &config.title_attribute).unwrap_or_default();
        let mut memberships = BTreeSet::new();
        if let Some(values) = user.attrs.get(&config.group_attribute) {
            memberships.extend(values.iter().filter_map(|value| {
                group_graph
                    .names
                    .get(&normalize_dn(value))
                    .cloned()
                    .or_else(|| group_name_from_dn(value))
            }));
        }
        memberships.extend(group_graph.groups_for_member(&user.dn, config.nested_group_depth));
        let active = config.disabled_attribute.as_ref().is_none_or(|attribute| {
            let disabled_values: BTreeSet<_> = config
                .disabled_values
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect();
            !user.attrs.get(attribute).is_some_and(|values| {
                values.iter().any(|value| disabled_values.contains(&value.to_ascii_lowercase()))
            })
        });
        entries.push(crate::models::LdapSnapshotEntry {
            external_id,
            email,
            name,
            title,
            groups: memberships.into_iter().collect(),
            active,
        });
    }
    let count = entries.len();
    identity::apply_ldap_snapshot(
        pool,
        provider_id,
        crate::models::LdapSyncSnapshot { complete: true, entries },
    )
    .await?;
    Ok(count)
}

pub async fn sync_due_ldap(pool: &SqlitePool, secrets: &SecretBox) -> Result<usize, ApiError> {
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM identity_providers
         WHERE kind='ldap' AND enabled=1 AND sync_interval_seconds IS NOT NULL
           AND (last_successful_sync_at IS NULL
             OR julianday(last_successful_sync_at) + (sync_interval_seconds / 86400.0) <= julianday('now'))
         ORDER BY priority,name",
    )
    .fetch_all(pool)
    .await?;
    let mut completed = 0;
    for id in ids {
        let provider_id = parse_uuid(&id)?;
        match tokio::time::timeout(
            Duration::from_secs(120),
            sync_ldap_provider(pool, secrets, provider_id),
        )
        .await
        {
            Ok(Ok(count)) => {
                tracing::info!(%provider_id, entries = count, "LDAP full sync complete");
                completed += 1;
            }
            Ok(Err(error)) => tracing::error!(%provider_id, %error, "LDAP full sync failed; previous state retained"),
            Err(_) => tracing::error!(%provider_id, "LDAP full sync timed out; previous state retained"),
        }
    }
    Ok(completed)
}

async fn paged_search(
    ldap: &mut Ldap,
    page_size: u32,
    base: &str,
    filter: &str,
    attributes: Vec<&str>,
) -> Result<Vec<SearchEntry>, ApiError> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(page_size as i32)),
    ];
    let mut search = ldap
        .streaming_search_with(adapters, base, Scope::Subtree, filter, attributes)
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("LDAP search failed: {error}")))?;
    let mut entries = Vec::new();
    while let Some(entry) = search
        .next()
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("LDAP search stream failed: {error}")))?
    {
        entries.push(SearchEntry::construct(entry));
        if entries.len() > 100_000 {
            return Err(ApiError::Validation("LDAP result exceeds 100,000 entries".into()));
        }
    }
    search
        .finish()
        .await
        .success()
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("LDAP search was incomplete: {error}")))?;
    Ok(entries)
}

#[derive(Default)]
struct GroupGraph {
    parents: HashMap<String, BTreeSet<String>>,
    names: HashMap<String, String>,
}

impl GroupGraph {
    fn groups_for_member(&self, member: &str, nested_depth: u8) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let mut frontier = BTreeSet::from([normalize_dn(member)]);
        let mut visited = BTreeSet::new();
        for _ in 0..=nested_depth {
            let mut next = BTreeSet::new();
            for node in frontier {
                if !visited.insert(node.clone()) { continue; }
                for parent in self.parents.get(&node).into_iter().flatten() {
                    if let Some(name) = self.names.get(parent) { names.insert(name.clone()); }
                    if !visited.contains(parent) { next.insert(parent.clone()); }
                }
            }
            if next.is_empty() { break; }
            frontier = next;
        }
        names
    }
}

fn build_group_graph(config: &LdapConfig, entries: Vec<SearchEntry>) -> GroupGraph {
    let mut graph = GroupGraph::default();
    for entry in entries {
        let dn = normalize_dn(&entry.dn);
        let name = first_attribute(&entry, &config.group_name_attribute)
            .or_else(|| group_name_from_dn(&entry.dn));
        if let Some(name) = name { graph.names.insert(dn.clone(), name); }
        for member in entry.attrs.get(&config.group_member_attribute).into_iter().flatten() {
            graph.parents.entry(normalize_dn(member)).or_default().insert(dn.clone());
        }
    }
    graph
}

fn first_attribute(entry: &SearchEntry, attribute: &str) -> Option<String> {
    entry.attrs.get(attribute).and_then(|values| values.first()).cloned()
}

fn attribute_or_binary(entry: &SearchEntry, attribute: &str) -> Option<String> {
    first_attribute(entry, attribute).or_else(|| {
        entry.bin_attrs.get(attribute).and_then(|values| values.first()).map(|value| STANDARD.encode(value))
    })
}

fn normalize_dn(value: &str) -> String { value.trim().to_ascii_lowercase() }

fn group_name_from_dn(value: &str) -> Option<String> {
    value
        .split(',')
        .next()
        .and_then(|rdn| rdn.split_once('='))
        .map(|(_, name)| name.replace("\\,", ",").replace("\\=", "=").trim().to_owned())
        .filter(|name| !name.is_empty())
}

pub async fn start_oidc(
    pool: &SqlitePool,
    secrets: &SecretBox,
    provider_id: Uuid,
) -> Result<String, ApiError> {
    let provider = identity::get_provider(pool, provider_id).await?;
    if !provider.enabled || !matches!(provider.kind, ProviderKind::Oidc) {
        return Err(ApiError::Forbidden("OIDC realm is not enabled".into()));
    }
    let config = oidc_config(pool, secrets, provider_id).await?;
    let http_client = oidc_http_client()?;
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(config.issuer_url.clone())
            .map_err(|error| ApiError::Validation(error.to_string()))?,
        &http_client,
    )
    .await
    .map_err(|error| ApiError::Internal(anyhow::anyhow!("OIDC discovery failed: {error}")))?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_url.clone())
            .map_err(|error| ApiError::Validation(error.to_string()))?,
    );
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(OidcScope::new("openid".into()))
        .add_scope(OidcScope::new("email".into()))
        .add_scope(OidcScope::new("profile".into()))
        .set_pkce_challenge(challenge);
    for scope in config.scopes {
        if !matches!(scope.as_str(), "openid" | "email" | "profile") {
            request = request.add_scope(OidcScope::new(scope));
        }
    }
    let (url, state, nonce) = request.url();
    let id = Uuid::now_v7();
    let state_value = state.secret();
    let secret = OidcStateSecret {
        verifier: verifier.secret().into(),
        nonce: nonce.secret().into(),
    };
    let envelope = secrets
        .encrypt(&format!("oidc-state:{id}"), &secret)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let timestamp = chrono::Utc::now();
    sqlx::query(
        "INSERT INTO oidc_login_states(id,provider_id,state_hash,nonce_hash,pkce_verifier_envelope,redirect_uri,expires_at,created_at)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(provider_id.to_string())
    .bind(Sha256::digest(state_value.as_bytes()).as_slice())
    .bind(Sha256::digest(secret.nonce.as_bytes()).as_slice())
    .bind(envelope)
    .bind(config.redirect_url)
    .bind((timestamp + chrono::Duration::minutes(10)).to_rfc3339())
    .bind(timestamp.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(url.to_string())
}

pub async fn finish_oidc(
    pool: &SqlitePool,
    secrets: &SecretBox,
    code: &str,
    state: &str,
) -> Result<(Principal, String), ApiError> {
    let digest = Sha256::digest(state.as_bytes());
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT id,provider_id,pkce_verifier_envelope,redirect_uri FROM oidc_login_states
         WHERE state_hash=? AND consumed_at IS NULL AND expires_at>?",
    )
    .bind(digest.as_slice())
    .bind(chrono::Utc::now().to_rfc3339())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("OIDC state is invalid or expired".into()))?;
    let state_id = parse_uuid(&row.try_get::<String, _>("id")?)?;
    let provider_id = parse_uuid(&row.try_get::<String, _>("provider_id")?)?;
    let secret: OidcStateSecret = secrets
        .decrypt(
            &format!("oidc-state:{state_id}"),
            &row.try_get::<Vec<u8>, _>("pkce_verifier_envelope")?,
        )
        .map_err(|error| ApiError::Internal(error.into()))?;
    sqlx::query("UPDATE oidc_login_states SET consumed_at=? WHERE id=?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(state_id.to_string())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    let config = oidc_config(pool, secrets, provider_id).await?;
    let http_client = oidc_http_client()?;
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(config.issuer_url.clone())
            .map_err(|error| ApiError::Validation(error.to_string()))?,
        &http_client,
    )
    .await
    .map_err(|error| ApiError::Internal(anyhow::anyhow!("OIDC discovery failed: {error}")))?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(row.try_get::<String, _>("redirect_uri")?)
            .map_err(|error| ApiError::Validation(error.to_string()))?,
    );
    let token = client
        .exchange_code(AuthorizationCode::new(code.into()))
        .map_err(|error| ApiError::Unauthorized(format!("OIDC code exchange unavailable: {error}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(secret.verifier))
        .request_async(&http_client)
        .await
        .map_err(|error| ApiError::Unauthorized(format!("OIDC code exchange failed: {error}")))?;
    let id_token = token
        .id_token()
        .ok_or_else(|| ApiError::Unauthorized("OIDC provider returned no ID token".into()))?;
    let verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &Nonce::new(secret.nonce))
        .map_err(|error| ApiError::Unauthorized(format!("OIDC token verification failed: {error}")))?;
    if let Some(expected) = claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            token.access_token(),
            id_token
                .signing_alg()
                .map_err(|error| ApiError::Unauthorized(error.to_string()))?,
            id_token
                .signing_key(&verifier)
                .map_err(|error| ApiError::Unauthorized(error.to_string()))?,
        )
        .map_err(|error| ApiError::Unauthorized(error.to_string()))?;
        if actual != *expected {
            return Err(ApiError::Unauthorized(
                "OIDC access token substitution detected".into(),
            ));
        }
    }
    let email = claims
        .email()
        .map(|value| value.as_str().to_owned())
        .ok_or_else(|| ApiError::Forbidden("OIDC email claim is required".into()))?;
    let email_verified = claims.email_verified() == Some(true);
    let userinfo = fetch_userinfo(&http_client, &config, token.access_token().secret()).await?;
    let name = userinfo
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&email)
        .to_owned();
    let title = userinfo
        .get(&config.title_claim)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let groups = claim_strings(&userinfo, &config.groups_claim);
    let user = identity::apply_verified_oidc_claims(
        pool,
        provider_id,
        OidcClaims {
            subject: claims.subject().as_str().into(),
            email,
            email_verified,
            name,
            title,
            groups,
        },
    )
    .await?;
    auth::establish_session(pool, user.id, "auth.session.oidc").await
}

async fn oidc_config(
    pool: &SqlitePool,
    secrets: &SecretBox,
    provider_id: Uuid,
) -> Result<OidcConfig, ApiError> {
    let value = identity::provider_config(pool, secrets, provider_id).await?;
    serde_json::from_value(value).map_err(|error| ApiError::Internal(error.into()))
}

fn oidc_http_client() -> Result<openidconnect::reqwest::Client, ApiError> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| ApiError::Internal(error.into()))
}

async fn fetch_userinfo(
    client: &openidconnect::reqwest::Client,
    config: &OidcConfig,
    access_token: &str,
) -> Result<serde_json::Value, ApiError> {
    let Some(url) = &config.userinfo_url else {
        return Ok(serde_json::Value::Object(Default::default()));
    };
    if !url.starts_with("https://") {
        return Err(ApiError::Validation("OIDC userinfo_url must use HTTPS".into()));
    }
    let response = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("OIDC userinfo failed: {error}")))?
        .error_for_status()
        .map_err(|error| ApiError::Unauthorized(format!("OIDC userinfo failed: {error}")))?;
    response
        .json()
        .await
        .map_err(|error| ApiError::Unauthorized(format!("OIDC userinfo was invalid: {error}")))
}

fn claim_strings(value: &serde_json::Value, claim: &str) -> Vec<String> {
    match value.get(claim) {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        Some(serde_json::Value::String(value)) => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    value
        .parse()
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid UUID: {error}")))
}

fn parse_kind(value: &str) -> Result<ProviderKind, ApiError> {
    match value {
        "oidc" => Ok(ProviderKind::Oidc),
        "ldap" => Ok(ProviderKind::Ldap),
        _ => Err(ApiError::Internal(anyhow::anyhow!("invalid provider kind"))),
    }
}
