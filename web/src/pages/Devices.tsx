import { useEffect, useRef, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import { Card, Empty, Field, Loading, Notice, PageHeader, Status, formatDate } from "../components/ui";
import { api, json } from "../lib/api";
import { renderConfig, downloadText } from "../lib/config";
import { derivePublicKey, generateKeyPair } from "../lib/keys";
import { useResource } from "../lib/hooks";
import type { AuthUser, Device, DeviceConfig } from "../types";

export default function Devices({ user }: { user: AuthUser }) {
  const resource = useResource<Device[]>("/api/v1/devices");
  const [selected, setSelected] = useState<Device | null>(null);
  const [configuration, setConfiguration] = useState<DeviceConfig | null>(null);
  const [newName, setNewName] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [newKeyNotice, setNewKeyNotice] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const canvas = useRef<HTMLCanvasElement>(null);

  async function choose(device: Device) {
    setSelected(device); setPrivateKey(""); setNewKeyNotice(false); setError(null);
    setConfiguration(await api(`/api/v1/devices/${device.id}/config`));
  }

  async function create(event: FormEvent) {
    event.preventDefault(); setError(null);
    try {
      const pair = generateKeyPair();
      const device = await api<Device>("/api/v1/devices", json("POST", { user_id: user.id, name: newName, public_key: pair.publicKey }));
      setPrivateKey(pair.privateKey); setNewKeyNotice(true); setNewName(""); setShowCreate(false);
      await resource.reload(); setSelected(device); setConfiguration(await api(`/api/v1/devices/${device.id}/config`));
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not create device"); }
  }

  let privateKeyError: string | null = null;
  if (privateKey && selected) {
    try { if (derivePublicKey(privateKey) !== selected.public_key) privateKeyError = "This private key does not match the registered device."; }
    catch (caught) { privateKeyError = caught instanceof Error ? caught.message : "Invalid private key"; }
  }
  const complete = Boolean(privateKey && !privateKeyError && configuration);

  useEffect(() => {
    if (complete && canvas.current && configuration) {
      void QRCode.toCanvas(canvas.current, renderConfig(configuration.model, privateKey), { width: 220, margin: 1, color: { dark: "#101820", light: "#ffffff" } });
    }
  }, [complete, configuration, privateKey]);

  async function acknowledge(method: "complete_download" | "placeholder_download" | "manual_dismiss") {
    if (!selected || !configuration) return;
    await api(`/api/v1/devices/${selected.id}/config/ack`, json("POST", { revision: configuration.model.revision, method }));
    await resource.reload();
    const refreshed = await api<Device>(`/api/v1/devices/${selected.id}`);
    setSelected(refreshed); setConfiguration(await api(`/api/v1/devices/${selected.id}/config`));
  }

  async function download(usePrivateKey: boolean) {
    if (!selected || !configuration) return;
    if (usePrivateKey && !complete) { setError(privateKeyError || "Supply the matching private key first."); return; }
    const contents = renderConfig(configuration.model, usePrivateKey ? privateKey : undefined);
    downloadText(`${selected.name.replace(/[^a-z0-9_-]+/gi, "-")}.conf`, contents);
    await acknowledge(usePrivateKey ? "complete_download" : "placeholder_download");
    if (usePrivateKey) { setPrivateKey(""); setNewKeyNotice(false); }
  }

  async function rotate() {
    if (!selected || !window.confirm(`Rotate the WireGuard key for ${selected.name}? The old key remains reserved until gateway acknowledgements arrive.`)) return;
    try {
      const pair = generateKeyPair();
      const device = await api<Device>(`/api/v1/devices/${selected.id}/key`, json("POST", { public_key: pair.publicKey }));
      setSelected(device); setPrivateKey(pair.privateKey); setNewKeyNotice(true); setConfiguration(await api(`/api/v1/devices/${device.id}/config`)); await resource.reload();
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not rotate key"); }
  }

  async function remove() {
    if (!selected || !window.confirm(`Revoke and delete ${selected.name}? Its address remains quarantined until every gateway confirms removal.`)) return;
    await api(`/api/v1/devices/${selected.id}`, { method: "DELETE" }); setSelected(null); setConfiguration(null); setPrivateKey(""); await resource.reload();
  }

  if (resource.loading) return <Loading />;
  return <>
    <PageHeader eyebrow="Self-service WireGuard" title="My devices" description="Private keys are created and handled only in this browser. WireMesh receives the public half and never stores the secret." action={<button className="button primary" onClick={() => setShowCreate(!showCreate)}>Add device</button>} />
    {(resource.error || error) && <Notice tone="danger">{resource.error || error}</Notice>}
    {showCreate && <Card className="form-card"><form className="inline-form compact-form" onSubmit={create}><Field label="Device name" hint="Use a name you will recognize later."><input required maxLength={80} placeholder="work-laptop" value={newName} onChange={(e) => setNewName(e.target.value)} /></Field><button className="button primary">Generate key & add</button></form></Card>}
    <div className="split-view device-view">
      <Card><div className="selection-list device-list">{resource.data?.filter((device) => device.status !== "deleted").map((device) => <button key={device.id} className={selected?.id === device.id ? "selected" : ""} onClick={() => choose(device)}><span><strong>{device.name}</strong><small>{device.vpn_address} · revision {device.config_revision}</small></span>{device.status !== "active" ? <Status tone="bad">{device.status}</Status> : device.outdated ? <Status tone="warn">Update</Status> : <Status tone="good">Current</Status>}</button>)}</div>{!resource.data?.filter((device) => device.status !== "deleted").length && <Empty>You have no devices. Create one to generate your first profile.</Empty>}</Card>
      <Card>{selected && configuration ? <><div className="site-detail"><div><p className="eyebrow">{selected.vpn_address}</p><h2>{selected.name}</h2><p>Created {formatDate(selected.created_at)}</p></div>{selected.outdated ? <Status tone="warn">Profile update available</Status> : <Status tone="good">Acknowledged r{selected.acknowledged_revision}</Status>}</div>
        {newKeyNotice && <Notice tone="success"><strong>This is the only copy of the new private key.</strong> Download a complete profile now or copy the key before leaving this page.</Notice>}
        {configuration.outdated && <div className="diff-panel"><p className="eyebrow">Changes since revision {configuration.acknowledged_revision || "none"}</p>{configuration.changes.length ? <ul>{configuration.changes.map((change, index) => <li key={`${change.kind}-${index}`}><span>{change.kind.replaceAll("_", " ")}</span>{change.description}</li>)}</ul> : <p>The registered key changed; download the profile created with the new browser key.</p>}<button className="text-button" onClick={() => acknowledge("manual_dismiss")}>I updated this manually · dismiss</button></div>}
        <div className="key-workspace"><Field label="Client private key" hint="Optional. It is checked locally against the registered public key and is never sent to the server."><textarea className="code-input" rows={3} placeholder="Leave blank for a placeholder profile" value={privateKey} onChange={(e) => setPrivateKey(e.target.value.trim())} /></Field>{privateKeyError && <p className="field-error">{privateKeyError}</p>}<div className="download-actions"><button className="button primary" disabled={!complete} onClick={() => download(true)}>Download complete profile</button><button className="button ghost" onClick={() => download(false)}>Download placeholder</button></div></div>
        {complete && <div className="qr-panel"><canvas ref={canvas} /><div><h3>Scan on a trusted device</h3><p>This QR code exists only in browser memory and disappears when the private key field is cleared.</p><button className="text-button" onClick={() => setPrivateKey("")}>Clear private key & QR</button></div></div>}
        <div className="peer-summary"><p className="eyebrow">Authorized sites</p>{configuration.peer_statuses.length ? configuration.peer_statuses.map((provisioning) => { const peer = configuration.model.peers.find((candidate) => candidate.site_id === provisioning.site_id); return <div key={provisioning.site_id}><span className={`gateway-dot ${provisioning.state}`} /><span><strong>{provisioning.site_name} · {provisioning.state}</strong><small>{provisioning.error || (peer ? `${peer.allowed_ips.join(", ")} via ${peer.endpoint}` : "Waiting for the gateway public key and endpoint reconciliation.")}</small></span></div>; }) : <Empty>No site grants are active for this account.</Empty>}</div>
        <div className="danger-actions"><button className="button ghost" onClick={rotate}>Rotate key</button><button className="button danger" onClick={remove}>Revoke device</button></div>
      </> : <Empty>Select a device to download its profile, inspect changes, or rotate its key.</Empty>}</Card>
    </div>
  </>;
}
