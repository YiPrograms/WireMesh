import { useState, type ChangeEvent, type FormEvent } from "react";
import { Card, Empty, Field, Loading, Notice, PageHeader, Status, formatDate } from "../components/ui";
import { api, json } from "../lib/api";
import { useResource } from "../lib/hooks";
import type { Acl, AclRule, Agent, Group, RouterTarget, Site, User } from "../types";

function csv(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function selectedValues(event: ChangeEvent<HTMLSelectElement>): string[] {
  return Array.from(event.currentTarget.selectedOptions, (option) => option.value);
}

function gatewayState(site: Site): "ready" | "pending" | "error" | "stale" {
  if (site.gateway_status === "error" || site.last_error) return "error";
  const fresh = site.last_seen_at !== null
    && Date.now() - new Date(site.last_seen_at).getTime() < 45_000;
  if (!fresh) return "stale";
  return site.desired_revision === site.applied_revision ? "ready" : "pending";
}

interface SiteDraft {
  name: string;
  routes: string;
  endpointHost: string;
  publicPort: string;
  groupIds: string[];
  aclDefault: "allow" | "deny";
  compatibilityAddress: boolean;
}

interface RouterDraft {
  baseUrl: string;
  username: string;
  password: string;
  caCertificate: string;
}

export default function Sites() {
  const sites = useResource<Site[]>("/api/v1/sites");
  const agents = useResource<Agent[]>("/api/v1/agents");
  const groups = useResource<Group[]>("/api/v1/groups");
  const users = useResource<User[]>("/api/v1/users");
  const [selected, setSelected] = useState<Site | null>(null);
  const [draft, setDraft] = useState<SiteDraft | null>(null);
  const [acl, setAcl] = useState<Acl | null>(null);
  const [routerTarget, setRouterTarget] = useState<RouterTarget | null>(null);
  const [routerDraft, setRouterDraft] = useState<RouterDraft>({ baseUrl: "", username: "", password: "", caCertificate: "" });
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "", routes: "", kind: "linux", interfaceName: "wm0", endpoint: "",
    port: "51820", agentId: "", groupIds: [] as string[], compatibilityAddress: false,
  });

  async function choose(site: Site) {
    setSelected(site);
    setDraft({
      name: site.name,
      routes: site.routes.join(", "),
      endpointHost: site.endpoint_host,
      publicPort: site.public_port?.toString() ?? "",
      groupIds: site.granted_group_ids,
      aclDefault: site.acl_default,
      compatibilityAddress: site.compatibility_address,
    });
    setAcl(await api(`/api/v1/sites/${site.id}/acl`));
    if (site.gateway_kind === "mikrotik") {
      const target = await api<RouterTarget>(`/api/v1/sites/${site.id}/router`);
      setRouterTarget(target);
      setRouterDraft({ baseUrl: target.base_url, username: target.username, password: "", caCertificate: "" });
    } else {
      setRouterTarget(null);
      setRouterDraft({ baseUrl: "", username: "", password: "", caCertificate: "" });
    }
  }

  async function create(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await api("/api/v1/sites", json("POST", {
        name: form.name,
        routes: csv(form.routes),
        gateway_kind: form.kind,
        interface_name: form.interfaceName,
        endpoint_host: form.endpoint,
        public_port: Number(form.port) || null,
        listen_port: 51820,
        public_key: null,
        agent_id: form.agentId || null,
        granted_group_ids: form.groupIds,
        acl_default: "allow",
        compatibility_address: form.kind === "mikrotik" && form.compatibilityAddress,
      }));
      setShowCreate(false);
      await sites.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not create site");
    }
  }

  async function saveSite(event: FormEvent) {
    event.preventDefault();
    if (!selected || !draft) return;
    setError(null);
    try {
      const saved = await api<Site>(`/api/v1/sites/${selected.id}`, json("PUT", {
        name: draft.name,
        routes: csv(draft.routes),
        endpoint_host: draft.endpointHost,
        public_port: Number(draft.publicPort) || null,
        granted_group_ids: draft.groupIds,
        acl_default: draft.aclDefault,
        compatibility_address: selected.gateway_kind === "mikrotik" && draft.compatibilityAddress,
      }));
      setSelected(saved);
      await sites.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not update site");
    }
  }

  async function saveAcl(next: Acl) {
    if (!selected) return;
    setError(null);
    try {
      const saved = await api<Acl>(`/api/v1/sites/${selected.id}/acl`, json("PUT", next));
      setAcl(saved);
      await sites.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not save ACL");
    }
  }

  async function saveRouterTarget(event: FormEvent) {
    event.preventDefault();
    if (!selected || selected.gateway_kind !== "mikrotik") return;
    setError(null);
    try {
      const saved = await api<RouterTarget>(`/api/v1/sites/${selected.id}/router`, json("PUT", {
        base_url: routerDraft.baseUrl,
        username: routerDraft.username,
        password: routerDraft.password || null,
        ca_certificate_pem: routerDraft.caCertificate || null,
      }));
      setRouterTarget(saved);
      setRouterDraft({ ...routerDraft, password: "", caCertificate: "" });
      const refreshed = await api<Site>(`/api/v1/sites/${selected.id}`);
      setSelected(refreshed);
      await sites.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not save RouterOS credentials");
    }
  }

  function updateRule(index: number, next: AclRule) {
    if (acl) setAcl({ ...acl, rules: acl.rules.map((rule, ruleIndex) => ruleIndex === index ? next : rule) });
  }

  function addRule() {
    if (!acl) return;
    setAcl({
      ...acl,
      rules: [...acl.rules, {
        position: (acl.rules.at(-1)?.position ?? 0) + 10,
        action: "allow",
        destination: selected?.routes[0] ?? "10.0.0.0/8",
        protocol: "any",
        destination_ports: null,
        user_ids: [],
        group_ids: [],
        enabled: true,
      }],
    });
  }

  if (sites.loading) return <Loading />;
  return <>
    <PageHeader eyebrow="Protected networks" title="Sites & policy" description="Each site has one exclusive gateway, non-overlapping routes, group grants, and a first-match forwarding policy." action={<button className="button primary" onClick={() => setShowCreate(!showCreate)}>Add site</button>} />
    {(sites.error || error) && <Notice tone="danger">{sites.error || error}</Notice>}
    <Notice>Offline gateways keep their last policy. Revocations remain pending until the assigned agent reconnects and acknowledges the new revision.</Notice>

    {showCreate && <Card className="form-card"><form className="form-grid" onSubmit={create}>
      <Field label="Site name"><input required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></Field>
      <Field label="Protected routes" hint="Comma-separated IPv4 CIDRs. Literal gateway endpoints cannot fall inside any protected route."><input required placeholder="10.40.0.0/16" value={form.routes} onChange={(event) => setForm({ ...form, routes: event.target.value })} /></Field>
      <Field label="Gateway type"><select value={form.kind} onChange={(event) => setForm({ ...form, kind: event.target.value, compatibilityAddress: false })}><option value="linux">Linux</option><option value="mikrotik">MikroTik</option></select></Field>
      <Field label="Assigned agent"><select required value={form.agentId} onChange={(event) => setForm({ ...form, agentId: event.target.value })}><option value="">Choose agent…</option>{agents.data?.filter((agent) => agent.kind === form.kind).map((agent) => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</select></Field>
      <Field label="WireGuard interface"><input required value={form.interfaceName} onChange={(event) => setForm({ ...form, interfaceName: event.target.value })} /></Field>
      <Field label="Public endpoint"><input required placeholder="vpn.example.com" value={form.endpoint} onChange={(event) => setForm({ ...form, endpoint: event.target.value })} /></Field>
      <Field label="Public UDP port"><input type="number" min="1" max="65535" value={form.port} onChange={(event) => setForm({ ...form, port: event.target.value })} /></Field>
      <Field label="Granted groups" hint="Use Ctrl/Cmd to select more than one."><select multiple value={form.groupIds} onChange={(event) => setForm({ ...form, groupIds: selectedValues(event) })}>{groups.data?.map((group) => <option key={group.id} value={group.id}>{group.display_name}</option>)}</select></Field>
      {form.kind === "mikrotik" && <label className="check-field"><input type="checkbox" checked={form.compatibilityAddress} onChange={(event) => setForm({ ...form, compatibilityAddress: event.target.checked })} /><span>Use reserved compatibility address</span></label>}
      <div className="form-actions"><button className="button primary">Create site</button></div>
    </form></Card>}

    <div className="split-view sites-view">
      <Card><div className="selection-list">{sites.data?.map((site) => { const state = gatewayState(site); return <button key={site.id} className={selected?.id === site.id ? "selected" : ""} onClick={() => choose(site)}><span><strong>{site.name}</strong><small>{site.routes.join(", ")}</small></span><Status tone={state === "ready" ? "good" : state === "error" ? "bad" : "warn"}>{state}</Status></button>; })}</div>{!sites.data?.length && <Empty>No sites configured.</Empty>}</Card>
      <Card>{selected && acl && draft ? <>
        <div className="site-detail"><div><p className="eyebrow">{selected.gateway_kind} gateway</p><h2>{selected.name}</h2><p>{selected.endpoint ?? "Awaiting endpoint facts"} · last seen {formatDate(selected.last_seen_at)}</p></div><div className="revision-block"><small>Applied / desired</small><strong>{selected.applied_revision} / {selected.desired_revision}</strong></div></div>
        {selected.last_error && <Notice tone="danger">{selected.last_error}</Notice>}
        <form className="site-settings" onSubmit={saveSite}>
          <Field label="Site name"><input required value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></Field>
          <Field label="Protected routes"><input required value={draft.routes} onChange={(event) => setDraft({ ...draft, routes: event.target.value })} /></Field>
          <Field label="Endpoint host"><input required value={draft.endpointHost} onChange={(event) => setDraft({ ...draft, endpointHost: event.target.value })} /></Field>
          <Field label="Public port" hint={`Blank uses reported listen port ${selected.listen_port ?? 51820}.`}><input type="number" min="1" max="65535" value={draft.publicPort} onChange={(event) => setDraft({ ...draft, publicPort: event.target.value })} /></Field>
          <Field label="Granted groups" hint="Use Ctrl/Cmd for multiple selections."><select multiple value={draft.groupIds} onChange={(event) => setDraft({ ...draft, groupIds: selectedValues(event) })}>{groups.data?.map((group) => <option key={group.id} value={group.id}>{group.display_name}</option>)}</select></Field>
          <Field label="Final ACL action"><select value={draft.aclDefault} onChange={(event) => { const value = event.target.value as "allow" | "deny"; setDraft({ ...draft, aclDefault: value }); setAcl({ ...acl, default_action: value }); }}><option value="allow">Allow</option><option value="deny">Deny</option></select></Field>
          {selected.gateway_kind === "mikrotik" && <label className="check-field"><input type="checkbox" checked={draft.compatibilityAddress} onChange={(event) => setDraft({ ...draft, compatibilityAddress: event.target.checked })} /><span>Use reserved first address for RouterOS compatibility</span></label>}
          <button className="button ghost">Save site settings</button>
        </form>

        {selected.gateway_kind === "mikrotik" && <form className="router-settings" onSubmit={saveRouterTarget}>
          <div className="router-settings-heading"><div><p className="eyebrow">Encrypted RouterOS target</p><h3>{routerTarget?.configured ? "Controller-managed credentials" : "Connection setup required"}</h3></div><Status tone={routerTarget?.configured ? "good" : "warn"}>{routerTarget?.configured ? "Configured" : "Missing"}</Status></div>
          <Field label="RouterOS HTTPS origin" hint="Do not include /rest."><input required placeholder="https://router.example.internal" value={routerDraft.baseUrl} onChange={(event) => setRouterDraft({ ...routerDraft, baseUrl: event.target.value })} /></Field>
          <Field label="RouterOS username"><input required autoComplete="off" value={routerDraft.username} onChange={(event) => setRouterDraft({ ...routerDraft, username: event.target.value })} /></Field>
          <Field label="RouterOS password" hint={routerTarget?.has_password ? "Leave blank to retain the encrypted password." : "Required for initial setup."}><input required={!routerTarget?.has_password} type="password" autoComplete="new-password" value={routerDraft.password} onChange={(event) => setRouterDraft({ ...routerDraft, password: event.target.value })} /></Field>
          <Field label="Router CA certificate (PEM)" hint={routerTarget?.has_ca_certificate ? "Leave blank to retain the encrypted CA bundle." : "Required. The connector will not use plain HTTP or disable verification."}><textarea required={!routerTarget?.has_ca_certificate} className="code-input" rows={5} value={routerDraft.caCertificate} onChange={(event) => setRouterDraft({ ...routerDraft, caCertificate: event.target.value })} /></Field>
          <button className="button ghost">Encrypt & publish target</button>
        </form>}

        <div className="policy-heading"><div><h3>Ordered access policy</h3><p>First matching rule wins. Empty subjects mean every user granted to this site.</p></div><button type="button" className="button ghost" onClick={addRule}>Add rule</button></div>
        <div className="acl-list">{acl.rules.map((rule, index) => <div className="acl-editor" key={rule.id ?? index}>
          <div className="acl-editor-main">
            <Field label="Order"><input type="number" value={rule.position} onChange={(event) => updateRule(index, { ...rule, position: Number(event.target.value) })} /></Field>
            <Field label="Action"><select value={rule.action} onChange={(event) => updateRule(index, { ...rule, action: event.target.value as "allow" | "deny" })}><option value="allow">Allow</option><option value="deny">Deny</option></select></Field>
            <Field label="Destination"><input value={rule.destination} onChange={(event) => updateRule(index, { ...rule, destination: event.target.value })} /></Field>
            <Field label="Protocol"><select value={rule.protocol} onChange={(event) => { const protocol = event.target.value as AclRule["protocol"]; updateRule(index, { ...rule, protocol, destination_ports: protocol === "tcp" || protocol === "udp" ? rule.destination_ports : null }); }}><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Field>
            {(rule.protocol === "tcp" || rule.protocol === "udp") && <><Field label="Port start"><input type="number" min="0" max="65535" value={rule.destination_ports?.start ?? ""} onChange={(event) => { const start = event.target.value === "" ? null : Number(event.target.value); updateRule(index, { ...rule, destination_ports: start === null ? null : { start, end: rule.destination_ports?.end ?? start } }); }} /></Field><Field label="Port end"><input type="number" min="0" max="65535" value={rule.destination_ports?.end ?? ""} onChange={(event) => { const end = event.target.value === "" ? null : Number(event.target.value); updateRule(index, { ...rule, destination_ports: end === null ? null : { start: rule.destination_ports?.start ?? end, end } }); }} /></Field></>}
          </div>
          <div className="acl-subjects">
            <Field label="Group subjects" hint="Empty means all granted users."><select multiple value={rule.group_ids} onChange={(event) => updateRule(index, { ...rule, group_ids: selectedValues(event) })}>{groups.data?.map((group) => <option key={group.id} value={group.id}>{group.display_name}</option>)}</select></Field>
            <Field label="User subjects"><select multiple value={rule.user_ids} onChange={(event) => updateRule(index, { ...rule, user_ids: selectedValues(event) })}>{users.data?.filter((user) => !user.soft_deleted).map((user) => <option key={user.id} value={user.id}>{user.name} · {user.email}</option>)}</select></Field>
            <label className="check-field"><input type="checkbox" checked={rule.enabled} onChange={(event) => updateRule(index, { ...rule, enabled: event.target.checked })} /><span>Enabled</span></label>
            <button type="button" className="button danger small" onClick={() => setAcl({ ...acl, rules: acl.rules.filter((_, ruleIndex) => ruleIndex !== index) })}>Delete rule</button>
          </div>
        </div>)}</div>
        <div className="policy-footer"><span>Final action: <strong>{acl.default_action}</strong></span><button className="button primary" onClick={() => saveAcl(acl)}>Publish policy</button></div>
      </> : <Empty>Select a site to inspect its gateway, grants, routes, and forwarding policy.</Empty>}</Card>
    </div>
  </>;
}
