import { useState, type ChangeEvent, type FormEvent } from "react";
import { Card, Empty, Field, Loading, Notice, PageHeader, Status, formatDate } from "../components/ui";
import { api, json } from "../lib/api";
import { useResource } from "../lib/hooks";
import type { ImportUsersPreview, IssuedToken, User } from "../types";

export default function Users() {
  const resource = useResource<User[]>("/api/v1/users");
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [title, setTitle] = useState("");
  const [importContent, setImportContent] = useState("");
  const [importFormat, setImportFormat] = useState<"csv" | "tsv">("csv");
  const [preview, setPreview] = useState<ImportUsersPreview | null>(null);
  const [issued, setIssued] = useState<IssuedToken | null>(null);

  async function create(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await api<User>("/api/v1/users", json("POST", { email, name, title }));
      setEmail(""); setName(""); setTitle(""); setShowCreate(false); await resource.reload();
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not create user"); }
  }

  async function toggle(user: User) {
    setError(null);
    try {
      await api(`/api/v1/users/${user.id}/disabled`, json("PATCH", { disabled: !user.manual_disabled }));
      await resource.reload();
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not update user"); }
  }

  async function lifecycle(user: User, action: "delete" | "restore" | "purge") {
    if ((action === "delete" || action === "purge") && !window.confirm(action === "purge" ? "Permanently purge this user after gateway removal acknowledgements? This cannot be undone." : "Soft-delete this user and revoke all gateway access?")) return;
    setError(null);
    try {
      const path = action === "delete" ? `/api/v1/users/${user.id}` : `/api/v1/users/${user.id}/${action}`;
      await api(path, { method: action === "restore" ? "POST" : "DELETE" });
      await resource.reload();
    } catch (caught) { setError(caught instanceof Error ? caught.message : `Could not ${action} user`); }
  }

  async function issueToken(user: User, purpose: "enrollment" | "reset") {
    setError(null);
    try {
      setIssued(await api<IssuedToken>(`/api/v1/users/${user.id}/${purpose}-token`, { method: "POST" }));
    } catch (caught) { setError(caught instanceof Error ? caught.message : `Could not issue ${purpose} token`); }
  }

  async function readImport(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setImportFormat(file.name.toLowerCase().endsWith(".tsv") ? "tsv" : "csv");
    setImportContent(await file.text());
    setPreview(null);
  }

  async function previewImport() {
    setError(null);
    try {
      setPreview(await api<ImportUsersPreview>("/api/v1/users/import/preview", json("POST", { format: importFormat, content: importContent })));
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not validate import"); }
  }

  async function applyImport() {
    setError(null);
    try {
      const result = await api<ImportUsersPreview>("/api/v1/users/import", json("POST", { format: importFormat, content: importContent }));
      setNotice(`Imported ${result.rows.length} rows: ${result.creates} created and ${result.links} linked.`);
      setShowImport(false); setPreview(null); setImportContent(""); await resource.reload();
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not apply import"); }
  }

  if (resource.loading) return <Loading />;
  return <>
    <PageHeader
      eyebrow="Directory"
      title="People"
      description="Canonical accounts are linked by normalized email, while profile fields remain owned by the source that created them."
      action={<div className="row-actions"><button className="button ghost" onClick={() => { setShowImport(!showImport); setShowCreate(false); }}>Import CSV / TSV</button><button className="button primary" onClick={() => { setShowCreate(!showCreate); setShowImport(false); }}>Add local user</button></div>}
    />
    {(resource.error || error) && <Notice tone="danger">{resource.error || error}</Notice>}
    {notice && <Notice tone="success">{notice}</Notice>}
    {issued && <Notice tone="success"><strong>Copy this {issued.purpose} token now.</strong> It is shown once; SMTP delivery is also queued when configured.<code className="secret">{issued.token}</code><button className="button ghost small" onClick={() => navigator.clipboard.writeText(issued.token)}>Copy token</button></Notice>}
    {showCreate && <Card className="form-card"><form className="inline-form" onSubmit={create}><Field label="Name"><input required value={name} onChange={(event) => setName(event.target.value)} /></Field><Field label="Email"><input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></Field><Field label="Title"><input value={title} onChange={(event) => setTitle(event.target.value)} /></Field><button className="button primary">Create</button></form></Card>}
    {showImport && <Card className="form-card import-card">
      <div className="card-heading"><div><h2>Preview directory import</h2><p>Required columns are <code>name</code> and <code>email</code>. Optional <code>title</code> and semicolon-separated <code>groups</code> are supported.</p></div></div>
      <div className="import-controls"><Field label="CSV or TSV file"><input type="file" accept=".csv,.tsv,text/csv,text/tab-separated-values" onChange={readImport} /></Field><Field label="Format"><select value={importFormat} onChange={(event) => { setImportFormat(event.target.value as "csv" | "tsv"); setPreview(null); }}><option value="csv">CSV</option><option value="tsv">TSV</option></select></Field><button className="button primary" disabled={!importContent} onClick={previewImport}>Validate preview</button></div>
      {preview && <><div className="import-summary"><Status tone={preview.valid ? "good" : "bad"}>{preview.valid ? "Ready" : `${preview.errors} errors`}</Status><span>{preview.creates} new users · {preview.links} existing accounts linked</span><button className="button primary small" disabled={!preview.valid} onClick={applyImport}>Apply import</button></div><div className="table-scroll preview-table"><table><thead><tr><th>Row</th><th>Person</th><th>Groups</th><th>Action</th></tr></thead><tbody>{preview.rows.slice(0, 100).map((row) => <tr key={row.row}><td>{row.row}</td><td><strong>{row.name || "Missing name"}</strong><br /><span className="muted">{row.email || row.errors.join("; ")}</span></td><td>{row.groups.join(", ") || "—"}</td><td><Status tone={row.action === "create" ? "good" : row.action === "link" ? "warn" : "bad"}>{row.action}</Status>{row.errors.length > 0 && <small className="row-error">{row.errors.join("; ")}</small>}</td></tr>)}</tbody></table>{preview.rows.length > 100 && <p className="muted preview-note">Showing the first 100 of {preview.rows.length} rows.</p>}</div></>}
    </Card>}
    <Card className="table-card">
      {resource.data?.length ? <div className="table-scroll"><table><thead><tr><th>Person</th><th>Status</th><th>Device limit</th><th>Created</th><th /></tr></thead><tbody>{resource.data.map((user) => <tr key={user.id}><td><div className="person-cell"><span className="avatar small">{user.name[0]?.toUpperCase()}</span><span><strong>{user.name}</strong><small>{user.email}{user.title ? ` · ${user.title}` : ""}</small></span></div></td><td>{user.purged ? <Status tone="neutral">Purged</Status> : user.soft_deleted ? <Status tone="bad">Soft-deleted</Status> : user.disabled ? <Status tone="bad">{user.manual_disabled ? "Manually disabled" : "LDAP disabled"}</Status> : <Status tone="good">Enabled</Status>}</td><td><input className="limit-input" disabled={user.soft_deleted} aria-label={`Device limit for ${user.name}`} type="number" min="1" max="100" value={user.device_limit} onChange={async (event) => { const limit = Number(event.target.value); if (limit) { await api(`/api/v1/users/${user.id}/device-limit`, json("PATCH", { limit })); await resource.reload(); } }} /></td><td>{formatDate(user.created_at)}</td><td><div className="row-actions user-actions">{!user.soft_deleted && <><button className="button ghost small" onClick={() => issueToken(user, "enrollment")}>Enroll</button><button className="button ghost small" onClick={() => issueToken(user, "reset")}>Reset</button><button className="button ghost small" onClick={() => toggle(user)}>{user.manual_disabled ? "Enable" : "Disable"}</button><button className="button ghost small" onClick={() => lifecycle(user, "delete")}>Delete</button></>}{user.soft_deleted && !user.purged && <><button className="button ghost small" onClick={() => lifecycle(user, "restore")}>Restore</button><button className="button danger small" onClick={() => lifecycle(user, "purge")}>Purge</button></>}</div></td></tr>)}</tbody></table></div> : <Empty>No users yet. Add a local user or connect an identity provider.</Empty>}
    </Card>
  </>;
}
