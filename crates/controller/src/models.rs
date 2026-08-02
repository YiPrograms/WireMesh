use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wiremesh_domain::{
    AclAction, ClientConfigModel, ClientOptions, ConfigChange, IpProtocol, PortRange,
};

#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct IssuedTokenResponse {
    pub user_id: Uuid,
    pub purpose: String,
    /// Returned once; the database stores only its digest and an encrypted mail-job copy.
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct LocalLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthUserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub is_admin: bool,
}

#[derive(Debug, Serialize)]
pub struct BootstrapResult {
    pub user_id: Uuid,
    pub enrollment_token: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct VersionResponse {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SystemSettingsResponse {
    pub client_pool: Ipv4Net,
    pub default_device_limit: u32,
    pub client_options: ClientOptions,
}

#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub users: i64,
    pub devices: i64,
    pub sites: i64,
    pub gateways_online: i64,
    pub gateways_stale: i64,
    pub client_pool: Ipv4Net,
    pub pool_capacity: u64,
    pub pool_allocated: i64,
    pub pool_quarantined: i64,
    pub pool_usage_percent: f64,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub name: String,
    #[serde(default)]
    pub title: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub title: String,
    pub manual_disabled: bool,
    pub ldap_disabled: bool,
    pub disabled: bool,
    pub soft_deleted: bool,
    pub purged: bool,
    pub device_limit: u32,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    Csv,
    Tsv,
}

#[derive(Debug, Deserialize)]
pub struct ImportUsersRequest {
    pub format: ImportFormat,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportUserRowResponse {
    pub row: usize,
    pub email: String,
    pub name: String,
    pub title: String,
    pub groups: Vec<String>,
    pub action: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ImportUsersPreviewResponse {
    pub valid: bool,
    pub creates: usize,
    pub links: usize,
    pub errors: usize,
    pub rows: Vec<ImportUserRowResponse>,
}

#[derive(Debug, Deserialize)]
pub struct SetUserDisabledRequest {
    pub disabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct GroupResponse {
    pub id: Uuid,
    pub normalized_name: String,
    pub display_name: String,
    pub members: i64,
}

#[derive(Debug, Deserialize)]
pub struct SetGroupMemberRequest {
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct GroupMemberResponse {
    pub user_id: Uuid,
    pub email: String,
    pub name: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayKindRequest {
    Linux,
    Mikrotik,
}

impl GatewayKindRequest {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Mikrotik => "mikrotik",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateSiteRequest {
    pub name: String,
    pub routes: Vec<Ipv4Net>,
    pub gateway_kind: GatewayKindRequest,
    pub interface_name: String,
    pub endpoint_host: String,
    pub public_port: Option<u16>,
    pub listen_port: Option<u16>,
    pub public_key: Option<String>,
    pub agent_id: Option<Uuid>,
    #[serde(default)]
    pub granted_group_ids: Vec<Uuid>,
    #[serde(default = "default_acl_action")]
    pub acl_default: AclAction,
    #[serde(default)]
    pub compatibility_address: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    pub name: String,
    pub kind: GatewayKindRequest,
}

#[derive(Debug, Serialize)]
pub struct CreatedAgentResponse {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    /// Returned once. Only its SHA-256 digest is persisted.
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub version: Option<String>,
    pub last_seen_at: Option<String>,
    pub online: bool,
}

#[derive(Debug, Serialize)]
pub struct RotatedAgentSecretResponse {
    pub agent_id: Uuid,
    /// Returned once. Only its SHA-256 digest is persisted as the overlapping next secret.
    pub secret: String,
}

fn default_acl_action() -> AclAction {
    AclAction::Allow
}

#[derive(Debug, Serialize)]
pub struct SiteResponse {
    pub id: Uuid,
    pub name: String,
    pub routes: Vec<Ipv4Net>,
    pub acl_default: AclAction,
    pub gateway_id: Uuid,
    pub gateway_kind: String,
    pub gateway_status: String,
    pub interface_name: String,
    pub endpoint_host: String,
    pub public_port: Option<u16>,
    pub listen_port: Option<u16>,
    pub endpoint: Option<String>,
    pub public_key: Option<String>,
    pub compatibility_address: bool,
    pub granted_group_ids: Vec<Uuid>,
    pub desired_revision: u64,
    pub applied_revision: u64,
    pub last_seen_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSiteRequest {
    pub name: String,
    pub routes: Vec<Ipv4Net>,
    pub endpoint_host: String,
    pub public_port: Option<u16>,
    pub granted_group_ids: Vec<Uuid>,
    pub acl_default: AclAction,
    #[serde(default)]
    pub compatibility_address: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRouterTargetRequest {
    pub base_url: String,
    pub username: String,
    /// Omit to retain the current password. Required for initial setup.
    pub password: Option<String>,
    /// Omit to retain the current PEM CA bundle. Required for initial setup.
    pub ca_certificate_pem: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RouterTargetResponse {
    pub configured: bool,
    pub base_url: String,
    pub username: String,
    pub has_password: bool,
    pub has_ca_certificate: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AclRuleModel {
    pub id: Option<Uuid>,
    pub position: u32,
    pub action: AclAction,
    pub destination: Ipv4Net,
    pub protocol: IpProtocol,
    pub destination_ports: Option<PortRange>,
    #[serde(default)]
    pub user_ids: Vec<Uuid>,
    #[serde(default)]
    pub group_ids: Vec<Uuid>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct ReplaceAclRequest {
    pub default_action: AclAction,
    pub rules: Vec<AclRuleModel>,
}

#[derive(Debug, Serialize)]
pub struct AclResponse {
    pub default_action: AclAction,
    pub rules: Vec<AclRuleModel>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSystemSettingsRequest {
    pub client_pool: Ipv4Net,
    pub default_device_limit: u32,
    pub client_options: ClientOptions,
}

#[derive(Debug, Deserialize)]
pub struct SetDeviceLimitRequest {
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AuditEventResponse {
    pub id: Uuid,
    pub occurred_at: String,
    pub actor_user_id: Option<Uuid>,
    pub actor_kind: String,
    pub action: String,
    pub object_kind: String,
    /// Object identifiers are opaque because some audited resources are
    /// singletons rather than UUID-backed domain entities.
    pub object_id: Option<String>,
    pub outcome: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Oidc,
    Ldap,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Ldap => "ldap",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateProviderRequest {
    pub kind: ProviderKind,
    pub name: String,
    #[serde(default)]
    pub trusted_create: bool,
    pub sync_interval_seconds: Option<u32>,
    pub config: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ProviderResponse {
    pub id: Uuid,
    pub kind: ProviderKind,
    pub name: String,
    pub enabled: bool,
    pub trusted_create: bool,
    pub sync_interval_seconds: Option<u32>,
    pub last_successful_sync_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginProviderResponse {
    pub id: Uuid,
    pub kind: ProviderKind,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct LdapLoginRequest {
    pub provider_id: Uuid,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SetProviderEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LdapSnapshotEntry {
    pub external_id: String,
    pub email: String,
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default = "default_true")]
    pub active: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LdapSyncSnapshot {
    pub complete: bool,
    pub entries: Vec<LdapSnapshotEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcClaims {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSubnetMigrationRequest {
    pub new_pool: Ipv4Net,
    pub effective_at: String,
}

#[derive(Debug, Serialize)]
pub struct SubnetMigrationResponse {
    pub id: Uuid,
    pub old_pool: Ipv4Net,
    pub new_pool: Ipv4Net,
    pub effective_at: String,
    pub status: String,
    pub prepared_gateways: i64,
    pub total_gateways: i64,
    pub affected_devices: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpSecurity {
    StartTls,
    Tls,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSmtpSettingsRequest {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub username: Option<String>,
    /// Omit to retain the existing credential. An empty value clears it.
    pub password: Option<String>,
    pub from_address: String,
    pub public_base_url: String,
}

#[derive(Debug, Serialize)]
pub struct SmtpSettingsResponse {
    pub configured: bool,
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub username: Option<String>,
    pub has_password: bool,
    pub from_address: String,
    pub public_base_url: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateDeviceRequest {
    pub user_id: Uuid,
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub vpn_address: Ipv4Addr,
    pub status: String,
    pub config_revision: u64,
    pub acknowledged_revision: u64,
    pub outdated: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct RotateDeviceKeyRequest {
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementMethod {
    CompleteDownload,
    PlaceholderDownload,
    ManualDismiss,
}

impl AcknowledgementMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CompleteDownload => "complete_download",
            Self::PlaceholderDownload => "placeholder_download",
            Self::ManualDismiss => "manual_dismiss",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AcknowledgeConfigRequest {
    pub revision: u64,
    pub method: AcknowledgementMethod,
}

#[derive(Debug, Serialize)]
pub struct DeviceConfigResponse {
    pub model: ClientConfigModel,
    pub placeholder_config: String,
    pub acknowledged_revision: u64,
    pub outdated: bool,
    pub changes: Vec<ConfigChange>,
    pub peer_statuses: Vec<PeerProvisioningResponse>,
}

#[derive(Debug, Serialize)]
pub struct PeerProvisioningResponse {
    pub site_id: Uuid,
    pub site_name: String,
    pub state: String,
    pub error: Option<String>,
}
