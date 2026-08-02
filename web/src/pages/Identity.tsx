import { useState, type FormEvent } from "react";
import { Card, Empty, Field, Loading, Notice, PageHeader, Status, formatDate } from "../components/ui";
import { api, json } from "../lib/api";
import { useResource } from "../lib/hooks";
import type { Provider } from "../types";

const oidcExample = JSON.stringify({ issuer_url: "https://id.example.com", client_id: "wiremesh", client_secret: "replace-me", redirect_url: "https://wiremesh.example.com/api/v1/auth/oidc/callback", userinfo_url: "https://id.example.com/userinfo", groups_claim: "groups" }, null, 2);
const ldapExample = JSON.stringify({ url: "ldaps://ldap.example.com", bind_dn: "cn=wiremesh,dc=example,dc=com", bind_password: "replace-me", base_dn: "ou=people,dc=example,dc=com", id_attribute: "entryUUID", email_attribute: "mail", name_attribute: "displayName" }, null, 2);

export default function Identity() {
  const resource = useResource<Provider[]>("/api/v1/identity/providers");
  const [showCreate, setShowCreate] = useState(false);
  const [kind, setKind] = useState<"oidc" | "ldap">("oidc");
  const [name, setName] = useState("");
  const [trusted, setTrusted] = useState(false);
  const [interval, setInterval] = useState("300");
  const [config, setConfig] = useState(oidcExample);
  const [error, setError] = useState<string | null>(null);

  function changeKind(value: "oidc" | "ldap") { setKind(value); setConfig(value === "oidc" ? oidcExample : ldapExample); }
  async function create(event: FormEvent) { event.preventDefault(); try { await api("/api/v1/identity/providers", json("POST", { kind, name, trusted_create: trusted, sync_interval_seconds: kind === "ldap" ? Number(interval) : null, config: JSON.parse(config) })); setShowCreate(false); await resource.reload(); } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not create provider"); } }
  async function toggle(provider: Provider) { try { await api(`/api/v1/identity/providers/${provider.id}/enabled`, json("PATCH", { enabled: !provider.enabled })); await resource.reload(); } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not update provider"); } }

  if (resource.loading) return <Loading />;
  return <><PageHeader eyebrow="Identity federation" title="Authentication realms" description="Users choose a specific local, LDAP, or OpenID Connect realm. Provider credentials are encrypted outside the database trust boundary." action={<button className="button primary" onClick={() => setShowCreate(!showCreate)}>Connect provider</button>} />
    {(resource.error || error) && <Notice tone="danger">{resource.error || error}</Notice>}
    <Notice>LDAP groups take precedence whenever a user has a linked LDAP identity. OIDC group removals take effect on the next login; the source badges in Groups show the active provenance.</Notice>
    {showCreate && <Card className="form-card"><form className="form-grid" onSubmit={create}><Field label="Provider name"><input required value={name} onChange={(e) => setName(e.target.value)} /></Field><Field label="Realm type"><select value={kind} onChange={(e) => changeKind(e.target.value as "oidc" | "ldap")}><option value="oidc">OpenID Connect</option><option value="ldap">LDAP directory</option></select></Field>{kind === "oidc" ? <Field label="Account creation"><select value={trusted ? "trusted" : "link"} onChange={(e) => setTrusted(e.target.value === "trusted")}><option value="link">Link-only</option><option value="trusted">Trusted · may create users</option></select></Field> : <Field label="Full-sync interval (seconds)"><input type="number" min="60" value={interval} onChange={(e) => setInterval(e.target.value)} /></Field>}<Field label="Encrypted provider configuration" hint="The complete object is sealed with XChaCha20-Poly1305 before SQLite storage."><textarea className="code-input" rows={10} value={config} onChange={(e) => setConfig(e.target.value)} /></Field><div className="form-actions"><button className="button primary">Save provider</button></div></form></Card>}
    <div className="card-grid">{resource.data?.map((provider) => <Card key={provider.id}><div className="card-heading"><span className="provider-kind">{provider.kind.toUpperCase()}</span><Status tone={provider.enabled ? "good" : "neutral"}>{provider.enabled ? "Enabled" : "Disabled"}</Status></div><h2>{provider.name}</h2><p>{provider.kind === "ldap" ? `Full sync every ${provider.sync_interval_seconds}s` : provider.trusted_create ? "Trusted account creation" : "Link-only account access"}</p><dl><div><dt>Last successful sync</dt><dd>{formatDate(provider.last_successful_sync_at)}</dd></div></dl><button className="button ghost" onClick={() => toggle(provider)}>{provider.enabled ? "Disable realm" : "Enable realm"}</button></Card>)}</div>
    {!resource.data?.length && <Card><Empty>No external realms. Local administrator-controlled accounts remain available.</Empty></Card>}
  </>;
}
