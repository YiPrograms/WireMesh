use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware,
    response::{IntoResponse, Redirect},
    routing::{any, get, patch, post},
};
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer, request_id::MakeRequestUuid,
    request_id::SetRequestIdLayer, trace::TraceLayer,
    services::{ServeDir, ServeFile},
};
use uuid::Uuid;

use crate::{
    AppState, VERSION, db,
    auth::{self, Principal},
    error::ApiError,
    models::{
        AcknowledgeConfigRequest, CreateAgentRequest, CreateDeviceRequest, CreateGroupRequest,
        CreateProviderRequest, CreateSiteRequest, CreateUserRequest, EnrollRequest,
        CreateSubnetMigrationRequest, ImportUsersRequest, LdapLoginRequest,
        LocalLoginRequest,
        ReplaceAclRequest, RotateDeviceKeyRequest,
        SetDeviceLimitRequest, SetGroupMemberRequest, SetProviderEnabledRequest,
        SetUserDisabledRequest, UpdateRouterTargetRequest, UpdateSiteRequest,
        UpdateSmtpSettingsRequest, UpdateSystemSettingsRequest, VersionResponse,
    },
    service,
};

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/system", get(system).put(update_system))
        .route("/api/v1/system/smtp", get(smtp_settings).put(update_smtp_settings))
        .route("/api/v1/dashboard", get(dashboard))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/import/preview", post(preview_user_import))
        .route("/api/v1/users/import", post(apply_user_import))
        .route("/api/v1/users/{id}", get(get_user).delete(soft_delete_user))
        .route("/api/v1/users/{id}/restore", post(restore_user))
        .route("/api/v1/users/{id}/purge", axum::routing::delete(purge_user))
        .route("/api/v1/users/{id}/enrollment-token", post(issue_enrollment_token))
        .route("/api/v1/users/{id}/reset-token", post(issue_reset_token))
        .route("/api/v1/users/{id}/disabled", patch(set_user_disabled))
        .route("/api/v1/users/{id}/device-limit", patch(set_user_device_limit))
        .route("/api/v1/groups", get(list_groups).post(create_group))
        .route("/api/v1/groups/{id}/members", get(list_group_members).post(add_group_member))
        .route("/api/v1/groups/{id}/members/{user_id}", axum::routing::delete(remove_group_member))
        .route("/api/v1/sites", get(list_sites).post(create_site))
        .route("/api/v1/sites/{id}", get(get_site).put(update_site))
        .route("/api/v1/sites/{id}/router", get(get_router_target).put(update_router_target))
        .route("/api/v1/sites/{id}/acl", get(get_acl).put(replace_acl))
        .route("/api/v1/agents", get(list_agents).post(create_agent))
        .route("/api/v1/agents/{id}/secret", post(rotate_agent_secret))
        .route("/api/v1/agents/{id}/secret/promote", post(promote_agent_secret))
        .route("/api/v1/identity/providers", get(list_providers).post(create_provider))
        .route("/api/v1/identity/providers/{id}/enabled", patch(set_provider_enabled))
        .route("/api/v1/identity/providers/{id}/sync/ldap", post(sync_ldap_snapshot))
        .route("/api/v1/audit", get(list_audit_events))
        .route("/api/v1/migrations", get(list_migrations).post(create_migration))
        .route("/api/v1/migrations/{id}", get(get_migration))
        .route("/api/v1/migrations/{id}/arm", post(arm_migration))
        .route("/api/v1/migrations/{id}/cancel", post(cancel_migration))
        .route("/api/v1/devices", get(list_devices).post(create_device))
        .route(
            "/api/v1/devices/{id}",
            get(get_device).delete(delete_device),
        )
        .route("/api/v1/devices/{id}/key", post(rotate_device_key))
        .route("/api/v1/devices/{id}/config", get(device_config))
        .route("/api/v1/devices/{id}/config/ack", post(acknowledge_config))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));

    let web_directory = state.web_directory.clone();
    let router = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/version", get(version))
        .route("/api/v1/auth/enroll", post(enroll))
        .route("/api/v1/auth/reset", post(reset_password))
        .route("/api/v1/auth/login/local", post(login_local))
        .route("/api/v1/auth/login/ldap", post(login_ldap))
        .route("/api/v1/auth/providers", get(login_providers))
        .route("/api/v1/auth/oidc/{id}/start", get(start_oidc))
        .route("/api/v1/auth/oidc/callback", get(finish_oidc))
        .merge(protected)
        .route("/api", any(not_found))
        .route("/api/{*path}", any(not_found))
        .layer(CompressionLayer::new())
        .layer(SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new())
        .with_state(state);
    if let Some(directory) = web_directory {
        router.fallback_service(
            ServeDir::new(&directory).fallback(ServeFile::new(directory.join("index.html"))),
        )
    } else {
        router.fallback(not_found)
    }
}

async fn list_agents(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<crate::models::AgentResponse>>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::list_agents(&state.db).await?))
}

async fn create_agent(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<CreateAgentRequest>,
) -> Result<(StatusCode, Json<crate::models::CreatedAgentResponse>), ApiError> {
    principal.require_admin()?;
    Ok((
        StatusCode::CREATED,
        Json(service::create_agent(&state.db, request).await?),
    ))
}

async fn rotate_agent_secret(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::RotatedAgentSecretResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::rotate_agent_secret(&state.db, id).await?))
}

async fn promote_agent_secret(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    service::promote_agent_secret(&state.db, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_providers(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<crate::models::ProviderResponse>>, ApiError> {
    principal.require_admin()?;
    Ok(Json(crate::identity::list_providers(&state.db).await?))
}

async fn create_provider(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<CreateProviderRequest>,
) -> Result<(StatusCode, Json<crate::models::ProviderResponse>), ApiError> {
    principal.require_admin()?;
    Ok((
        StatusCode::CREATED,
        Json(crate::identity::create_provider(&state.db, &state.secrets, request).await?),
    ))
}

async fn set_provider_enabled(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<SetProviderEnabledRequest>,
) -> Result<Json<crate::models::ProviderResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        crate::identity::set_provider_enabled(&state.db, id, request.enabled).await?,
    ))
}

async fn sync_ldap_snapshot(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    principal.require_admin()?;
    let entries = crate::federated::sync_ldap_provider(&state.db, &state.secrets, id).await?;
    Ok(Json(serde_json::json!({"entries": entries})))
}

async fn enroll(
    State(state): State<AppState>,
    Json(request): Json<EnrollRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (principal, token) = match auth::enroll(&state.db, &request.token, &request.password).await {
        Ok(result) => result,
        Err(error) => {
            let _ = auth::record_auth_failure(&state.db, "auth.enroll").await;
            return Err(error);
        }
    };
    Ok((
        [(header::SET_COOKIE, auth::session_cookie(&token)?)],
        Json(principal.response()),
    ))
}

async fn reset_password(
    State(state): State<AppState>,
    Json(request): Json<EnrollRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (principal, token) = match auth::reset_password(&state.db, &request.token, &request.password).await {
        Ok(result) => result,
        Err(error) => {
            let _ = auth::record_auth_failure(&state.db, "auth.reset").await;
            return Err(error);
        }
    };
    Ok((
        [(header::SET_COOKIE, auth::session_cookie(&token)?)],
        Json(principal.response()),
    ))
}

async fn login_local(
    State(state): State<AppState>,
    Json(request): Json<LocalLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (principal, token) = match auth::login_local(&state.db, &request.email, &request.password).await {
        Ok(result) => result,
        Err(error) => {
            let _ = auth::record_auth_failure(&state.db, "auth.login.local").await;
            return Err(error);
        }
    };
    Ok((
        [(header::SET_COOKIE, auth::session_cookie(&token)?)],
        Json(principal.response()),
    ))
}

async fn login_providers(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::models::LoginProviderResponse>>, ApiError> {
    Ok(Json(crate::federated::login_providers(&state.db).await?))
}

async fn login_ldap(
    State(state): State<AppState>,
    Json(request): Json<LdapLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (principal, token) = match crate::federated::login_ldap(&state.db, &state.secrets, request).await {
        Ok(result) => result,
        Err(error) => {
            let _ = auth::record_auth_failure(&state.db, "auth.login.ldap").await;
            return Err(error);
        }
    };
    Ok((
        [(header::SET_COOKIE, auth::session_cookie(&token)?)],
        Json(principal.response()),
    ))
}

async fn start_oidc(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Redirect, ApiError> {
    let url = crate::federated::start_oidc(&state.db, &state.secrets, id).await?;
    Ok(Redirect::to(&url))
}

#[derive(serde::Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

async fn finish_oidc(
    State(state): State<AppState>,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let (_, token) = match crate::federated::finish_oidc(
        &state.db,
        &state.secrets,
        &query.code,
        &query.state,
    )
    .await {
        Ok(result) => result,
        Err(error) => {
            let _ = auth::record_auth_failure(&state.db, "auth.login.oidc").await;
            return Err(error);
        }
    };
    Ok((
        [(header::SET_COOKIE, auth::session_cookie(&token)?)],
        Redirect::to("/"),
    ))
}

async fn me(Extension(principal): Extension<Principal>) -> Json<crate::models::AuthUserResponse> {
    Json(principal.response())
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    auth::logout(&state.db, &headers).await?;
    Ok((
        [(header::SET_COOKIE, auth::clear_session_cookie())],
        StatusCode::NO_CONTENT,
    ))
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn ready(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    db::ready(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn metrics(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        service::prometheus_metrics(&state.db).await?,
    ))
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "wiremesh",
        version: VERSION,
    })
}

async fn system(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<crate::models::SystemSettingsResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::system_settings(&state.db).await?))
}

async fn update_system(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<UpdateSystemSettingsRequest>,
) -> Result<Json<crate::models::SystemSettingsResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::update_system_settings(&state.db, request).await?))
}

async fn smtp_settings(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<crate::models::SmtpSettingsResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(crate::mail::get_settings(&state.db, &state.secrets).await?))
}

async fn update_smtp_settings(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<UpdateSmtpSettingsRequest>,
) -> Result<Json<crate::models::SmtpSettingsResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        crate::mail::update_settings(&state.db, &state.secrets, principal.id, request).await?,
    ))
}

async fn dashboard(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<crate::models::DashboardResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::dashboard(&state.db).await?))
}

async fn list_users(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<crate::models::UserResponse>>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::list_users(&state.db).await?))
}

async fn create_user(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<crate::models::UserResponse>), ApiError> {
    principal.require_admin()?;
    Ok((
        StatusCode::CREATED,
        Json(service::create_user(&state.db, request).await?),
    ))
}

async fn preview_user_import(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<ImportUsersRequest>,
) -> Result<Json<crate::models::ImportUsersPreviewResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(crate::user_import::preview(&state.db, request).await?))
}

async fn apply_user_import(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<ImportUsersRequest>,
) -> Result<Json<crate::models::ImportUsersPreviewResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        crate::user_import::apply(&state.db, principal.id, request).await?,
    ))
}

async fn get_user(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::UserResponse>, ApiError> {
    principal.require_self_or_admin(id)?;
    Ok(Json(service::get_user(&state.db, id).await?))
}

async fn soft_delete_user(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::UserResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::soft_delete_user(&state.db, id).await?))
}

async fn restore_user(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::UserResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::restore_user(&state.db, id).await?))
}

async fn purge_user(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::UserResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::purge_user(&state.db, id).await?))
}

async fn issue_enrollment_token(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::IssuedTokenResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        auth::issue_enrollment_token(&state.db, &state.secrets, principal.id, id).await?,
    ))
}

async fn issue_reset_token(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::IssuedTokenResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        auth::issue_reset_token(&state.db, &state.secrets, principal.id, id).await?,
    ))
}

async fn set_user_disabled(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<SetUserDisabledRequest>,
) -> Result<Json<crate::models::UserResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        service::set_user_disabled(&state.db, id, request.disabled).await?,
    ))
}

async fn set_user_device_limit(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<SetDeviceLimitRequest>,
) -> Result<Json<crate::models::UserResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        service::set_user_device_limit(&state.db, id, request.limit).await?,
    ))
}

async fn list_groups(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<crate::models::GroupResponse>>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::list_groups(&state.db).await?))
}

async fn create_group(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<crate::models::GroupResponse>), ApiError> {
    principal.require_admin()?;
    Ok((
        StatusCode::CREATED,
        Json(service::create_group(&state.db, request).await?),
    ))
}

async fn list_group_members(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<crate::models::GroupMemberResponse>>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::list_group_members(&state.db, id).await?))
}

async fn add_group_member(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<SetGroupMemberRequest>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    service::add_local_group_member(&state.db, id, request.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_group_member(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    service::remove_local_group_member(&state.db, id, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_sites(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<crate::models::SiteResponse>>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::list_sites(&state.db).await?))
}

async fn create_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<CreateSiteRequest>,
) -> Result<(StatusCode, Json<crate::models::SiteResponse>), ApiError> {
    principal.require_admin()?;
    Ok((
        StatusCode::CREATED,
        Json(service::create_site(&state.db, request).await?),
    ))
}

async fn get_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::SiteResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::get_site(&state.db, id).await?))
}

async fn update_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateSiteRequest>,
) -> Result<Json<crate::models::SiteResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::update_site(&state.db, id, request).await?))
}

async fn get_router_target(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::RouterTargetResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        crate::router_target::get_for_site(&state.db, &state.secrets, id).await?,
    ))
}

async fn update_router_target(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateRouterTargetRequest>,
) -> Result<Json<crate::models::RouterTargetResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(
        crate::router_target::update_for_site(
            &state.db,
            &state.secrets,
            principal.id,
            id,
            request,
        )
        .await?,
    ))
}

async fn get_acl(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::AclResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::get_acl(&state.db, id).await?))
}

async fn replace_acl(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<ReplaceAclRequest>,
) -> Result<Json<crate::models::AclResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::replace_acl(&state.db, id, request).await?))
}

#[derive(serde::Deserialize)]
struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: u32,
}

fn default_audit_limit() -> u32 {
    100
}

async fn list_audit_events(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<crate::models::AuditEventResponse>>, ApiError> {
    principal.require_admin()?;
    Ok(Json(service::list_audit_events(&state.db, query.limit).await?))
}

async fn list_migrations(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<crate::models::SubnetMigrationResponse>>, ApiError> {
    principal.require_admin()?;
    Ok(Json(crate::migration::list(&state.db).await?))
}

async fn get_migration(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::SubnetMigrationResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(crate::migration::get(&state.db, id).await?))
}

async fn create_migration(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<CreateSubnetMigrationRequest>,
) -> Result<(StatusCode, Json<crate::models::SubnetMigrationResponse>), ApiError> {
    principal.require_admin()?;
    Ok((
        StatusCode::CREATED,
        Json(crate::migration::create(&state.db, principal.id, request).await?),
    ))
}

async fn arm_migration(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::SubnetMigrationResponse>, ApiError> {
    principal.require_admin()?;
    Ok(Json(crate::migration::arm(&state.db, principal.id, id).await?))
}

async fn cancel_migration(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    crate::migration::cancel(&state.db, principal.id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
struct DeviceQuery {
    user_id: Option<Uuid>,
}

async fn list_devices(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<DeviceQuery>,
) -> Result<Json<Vec<crate::models::DeviceResponse>>, ApiError> {
    let user_id = query.user_id.unwrap_or(principal.id);
    principal.require_self_or_admin(user_id)?;
    Ok(Json(
        service::list_devices_for_user(&state.db, user_id).await?,
    ))
}

async fn create_device(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<CreateDeviceRequest>,
) -> Result<(StatusCode, Json<crate::models::DeviceResponse>), ApiError> {
    principal.require_self_or_admin(request.user_id)?;
    Ok((
        StatusCode::CREATED,
        Json(service::create_device(&state.db, request).await?),
    ))
}

async fn get_device(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::DeviceResponse>, ApiError> {
    let device = service::get_device(&state.db, id).await?;
    principal.require_self_or_admin(device.user_id)?;
    Ok(Json(device))
}

async fn delete_device(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let device = service::get_device(&state.db, id).await?;
    principal.require_self_or_admin(device.user_id)?;
    service::delete_device(&state.db, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rotate_device_key(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<RotateDeviceKeyRequest>,
) -> Result<Json<crate::models::DeviceResponse>, ApiError> {
    let device = service::get_device(&state.db, id).await?;
    principal.require_self_or_admin(device.user_id)?;
    Ok(Json(
        service::rotate_device_key(&state.db, id, request).await?,
    ))
}

async fn device_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::DeviceConfigResponse>, ApiError> {
    let device = service::get_device(&state.db, id).await?;
    principal.require_self_or_admin(device.user_id)?;
    Ok(Json(service::device_config(&state.db, id).await?))
}

async fn acknowledge_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<AcknowledgeConfigRequest>,
) -> Result<Json<crate::models::DeviceResponse>, ApiError> {
    let device = service::get_device(&state.db, id).await?;
    principal.require_self_or_admin(device.user_id)?;
    Ok(Json(
        service::acknowledge_config(&state.db, id, request).await?,
    ))
}

async fn not_found() -> ApiError {
    ApiError::NotFound("route does not exist".into())
}
