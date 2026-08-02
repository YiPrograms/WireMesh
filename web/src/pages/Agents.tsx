import { useState, type FormEvent } from "react";
import { Card, Empty, Field, Loading, Notice, PageHeader, Status, formatDate } from "../components/ui";
import { api, json } from "../lib/api";
import { useResource } from "../lib/hooks";
import type { Agent, CreatedAgent, RotatedAgentSecret } from "../types";

export default function Agents() {
  const resource = useResource<Agent[]>("/api/v1/agents");
  const [name, setName] = useState("");
  const [kind, setKind] = useState("linux");
  const [created, setCreated] = useState<CreatedAgent | null>(null);
  const [rotated, setRotated] = useState<RotatedAgentSecret | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function create(event: FormEvent) { event.preventDefault(); try { const value = await api<CreatedAgent>("/api/v1/agents", json("POST", { name, kind })); setCreated(value); setName(""); await resource.reload(); } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not create agent"); } }
  async function rotate(agent: Agent) { setError(null); try { setCreated(null); setRotated(await api<RotatedAgentSecret>(`/api/v1/agents/${agent.id}/secret`, { method: "POST" })); } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not rotate agent secret"); } }
  async function promote(agent: Agent) { setError(null); try { await api(`/api/v1/agents/${agent.id}/secret/promote`, { method: "POST" }); setRotated(null); } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not promote agent secret"); } }
  if (resource.loading) return <Loading />;
  return <><PageHeader eyebrow="Outbound control channel" title="Gateway agents" description="Agents connect back over TLS with a unique 256-bit secret. Offline gateways keep their last state and remain visibly stale." />
    {(resource.error || error) && <Notice tone="danger">{resource.error || error}</Notice>}
    {created && <Notice tone="success"><strong>Copy this secret now.</strong> It is shown once and only its hash is stored.<code className="secret">{created.secret}</code><button className="button ghost small" onClick={() => navigator.clipboard.writeText(created.secret)}>Copy secret</button></Notice>}
    {rotated && <Notice tone="success"><strong>Install this next secret, then promote it.</strong> Both current and next credentials work during the overlap.<code className="secret">{rotated.secret}</code><button className="button ghost small" onClick={() => navigator.clipboard.writeText(rotated.secret)}>Copy secret</button></Notice>}
    <Card className="form-card"><form className="inline-form compact-form" onSubmit={create}><Field label="Agent name"><input required placeholder="gateway-cluster-east" value={name} onChange={(e) => setName(e.target.value)} /></Field><Field label="Backend"><select value={kind} onChange={(e) => setKind(e.target.value)}><option value="linux">Linux · WireGuard + nftables</option><option value="mikrotik">MikroTik · RouterOS REST</option></select></Field><button className="button primary">Create agent</button></form></Card>
    <div className="card-grid">{resource.data?.map((agent) => <Card key={agent.id}><div className="card-heading"><span className="backend-icon">{agent.kind === "linux" ? "Lx" : "Mk"}</span><Status tone={agent.online ? "good" : "warn"}>{agent.online ? "Online" : "Stale"}</Status></div><h2>{agent.name}</h2><p className="mono muted">{agent.id}</p><dl><div><dt>Backend</dt><dd>{agent.kind}</dd></div><div><dt>Version</dt><dd>{agent.version ?? "Not reported"}</dd></div><div><dt>Last seen</dt><dd>{formatDate(agent.last_seen_at)}</dd></div></dl><div className="row-actions"><button className="button ghost small" onClick={() => rotate(agent)}>Rotate secret</button><button className="button ghost small" onClick={() => promote(agent)}>Promote next</button></div></Card>)}</div>
    {!resource.data?.length && <Card><Empty>No agents yet. Create one, then assign it to a site.</Empty></Card>}
  </>;
}
