export type UUID = string;

export interface AuthUser {
  id: UUID;
  email: string;
  name: string;
  is_admin: boolean;
}

export interface ClientOptions {
  dns_servers: string[];
  search_domains: string[];
  mtu: number | null;
  persistent_keepalive: number | null;
}

export interface SystemSettings {
  client_pool: string;
  default_device_limit: number;
  client_options: ClientOptions;
}

export interface SubnetMigration {
  id: UUID;
  old_pool: string;
  new_pool: string;
  effective_at: string;
  status: "preparing" | "armed" | "applied" | "cancelled" | "failed";
  prepared_gateways: number;
  total_gateways: number;
  affected_devices: number;
}

export interface SmtpSettings {
  configured: boolean;
  enabled: boolean;
  host: string;
  port: number;
  security: "start_tls" | "tls";
  username: string | null;
  has_password: boolean;
  from_address: string;
  public_base_url: string;
}

export interface Dashboard {
  users: number;
  devices: number;
  sites: number;
  gateways_online: number;
  gateways_stale: number;
  client_pool: string;
  pool_capacity: number;
  pool_allocated: number;
  pool_quarantined: number;
  pool_usage_percent: number;
}

export interface User {
  id: UUID;
  email: string;
  name: string;
  title: string;
  manual_disabled: boolean;
  ldap_disabled: boolean;
  disabled: boolean;
  soft_deleted: boolean;
  purged: boolean;
  device_limit: number;
  created_at: string;
}

export interface ImportUserRow {
  row: number;
  email: string;
  name: string;
  title: string;
  groups: string[];
  action: "create" | "link" | "error";
  errors: string[];
}

export interface ImportUsersPreview {
  valid: boolean;
  creates: number;
  links: number;
  errors: number;
  rows: ImportUserRow[];
}

export interface IssuedToken {
  user_id: UUID;
  purpose: "enrollment" | "reset";
  token: string;
  expires_at: string;
}

export interface Group {
  id: UUID;
  normalized_name: string;
  display_name: string;
  members: number;
}

export interface GroupMember {
  user_id: UUID;
  email: string;
  name: string;
  sources: string[];
}

export interface Agent {
  id: UUID;
  name: string;
  kind: "linux" | "mikrotik";
  version: string | null;
  last_seen_at: string | null;
  online: boolean;
}

export interface CreatedAgent extends Agent {
  secret: string;
}

export interface RotatedAgentSecret {
  agent_id: UUID;
  secret: string;
}

export interface Site {
  id: UUID;
  name: string;
  routes: string[];
  acl_default: "allow" | "deny";
  gateway_id: UUID;
  gateway_kind: "linux" | "mikrotik";
  gateway_status: string;
  interface_name: string;
  endpoint_host: string;
  public_port: number | null;
  listen_port: number | null;
  endpoint: string | null;
  public_key: string | null;
  compatibility_address: boolean;
  granted_group_ids: UUID[];
  desired_revision: number;
  applied_revision: number;
  last_seen_at: string | null;
  last_error: string | null;
}

export interface RouterTarget {
  configured: boolean;
  base_url: string;
  username: string;
  has_password: boolean;
  has_ca_certificate: boolean;
}

export interface AclRule {
  id?: UUID;
  position: number;
  action: "allow" | "deny";
  destination: string;
  protocol: "any" | "tcp" | "udp" | "icmp";
  destination_ports: { start: number; end: number } | null;
  user_ids: UUID[];
  group_ids: UUID[];
  enabled: boolean;
}

export interface Acl {
  default_action: "allow" | "deny";
  rules: AclRule[];
}

export interface Device {
  id: UUID;
  user_id: UUID;
  name: string;
  public_key: string;
  vpn_address: string;
  status: string;
  config_revision: number;
  acknowledged_revision: number;
  outdated: boolean;
  created_at: string;
}

export interface ClientPeer {
  site_id: UUID;
  site_name: string;
  public_key: string;
  endpoint: string;
  allowed_ips: string[];
}

export interface ClientConfigModel {
  device_id: UUID;
  device_name: string;
  revision: number;
  address: string;
  options: ClientOptions;
  peers: ClientPeer[];
}

export interface ConfigChange {
  kind: "address" | "options" | "peer_added" | "peer_removed" | "peer_changed";
  site_id: UUID | null;
  description: string;
}

export interface DeviceConfig {
  model: ClientConfigModel;
  placeholder_config: string;
  acknowledged_revision: number;
  outdated: boolean;
  changes: ConfigChange[];
  peer_statuses: {
    site_id: UUID;
    site_name: string;
    state: "pending" | "ready" | "error";
    error: string | null;
  }[];
}

export interface Provider {
  id: UUID;
  kind: "oidc" | "ldap";
  name: string;
  enabled: boolean;
  trusted_create: boolean;
  sync_interval_seconds: number | null;
  last_successful_sync_at: string | null;
}

export interface LoginProvider {
  id: UUID;
  kind: "oidc" | "ldap";
  name: string;
}

export interface AuditEvent {
  id: UUID;
  occurred_at: string;
  actor_user_id: UUID | null;
  actor_kind: string;
  action: string;
  object_kind: string;
  object_id: string | null;
  outcome: string;
  details: unknown;
}
