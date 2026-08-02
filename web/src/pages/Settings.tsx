import { useEffect, useState, type FormEvent } from "react";
import {
  Card,
  Empty,
  Field,
  Loading,
  Notice,
  PageHeader,
  Status,
  formatDate,
} from "../components/ui";
import { api, json } from "../lib/api";
import { useResource } from "../lib/hooks";
import type { SmtpSettings, SubnetMigration, SystemSettings } from "../types";

export default function Settings() {
  const resource = useResource<SystemSettings>("/api/v1/system");
  const migrations = useResource<SubnetMigration[]>("/api/v1/migrations");
  const smtp = useResource<SmtpSettings>("/api/v1/system/smtp");
  const [form, setForm] = useState({
    pool: "",
    limit: "5",
    dns: "",
    domains: "",
    mtu: "",
    keepalive: "25",
  });
  const [migration, setMigration] = useState({ pool: "", at: "" });
  const [mail, setMail] = useState({
    enabled: false,
    host: "",
    port: "587",
    security: "start_tls" as "start_tls" | "tls",
    username: "",
    password: "",
    from: "",
    baseUrl: "",
  });
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!resource.data) return;
    setForm({
      pool: resource.data.client_pool,
      limit: String(resource.data.default_device_limit),
      dns: resource.data.client_options.dns_servers.join(", "),
      domains: resource.data.client_options.search_domains.join(", "),
      mtu: resource.data.client_options.mtu?.toString() ?? "",
      keepalive: resource.data.client_options.persistent_keepalive?.toString() ?? "",
    });
  }, [resource.data]);

  useEffect(() => {
    if (!smtp.data) return;
    setMail({
      enabled: smtp.data.enabled,
      host: smtp.data.host,
      port: String(smtp.data.port),
      security: smtp.data.security,
      username: smtp.data.username ?? "",
      password: "",
      from: smtp.data.from_address,
      baseUrl: smtp.data.public_base_url,
    });
  }, [smtp.data]);

  async function save(event: FormEvent) {
    event.preventDefault();
    setMessage(null);
    try {
      await api(
        "/api/v1/system",
        json("PUT", {
          client_pool: form.pool,
          default_device_limit: Number(form.limit),
          client_options: {
            dns_servers: form.dns.split(",").map((value) => value.trim()).filter(Boolean),
            search_domains: form.domains.split(",").map((value) => value.trim()).filter(Boolean),
            mtu: form.mtu ? Number(form.mtu) : null,
            persistent_keepalive: form.keepalive ? Number(form.keepalive) : null,
          },
        }),
      );
      setMessage("Settings published. Affected profiles now show a new revision.");
      await resource.reload();
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Could not save settings");
    }
  }

  async function saveMail(event: FormEvent) {
    event.preventDefault();
    setMessage(null);
    try {
      await api(
        "/api/v1/system/smtp",
        json("PUT", {
          enabled: mail.enabled,
          host: mail.host,
          port: Number(mail.port),
          security: mail.security,
          username: mail.username || null,
          password: mail.password || undefined,
          from_address: mail.from,
          public_base_url: mail.baseUrl,
        }),
      );
      setMessage("SMTP settings saved. Queued notifications will use the durable retry worker.");
      await smtp.reload();
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Could not save SMTP settings");
    }
  }

  async function createMigration(event: FormEvent) {
    event.preventDefault();
    setMessage(null);
    try {
      await api(
        "/api/v1/migrations",
        json("POST", {
          new_pool: migration.pool,
          effective_at: new Date(migration.at).toISOString(),
        }),
      );
      setMigration({ pool: "", at: "" });
      setMessage("Migration plan created. Arm it after every gateway reports prepared.");
      await migrations.reload();
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Could not create migration");
    }
  }

  async function migrationAction(id: string, action: "arm" | "cancel") {
    setMessage(null);
    try {
      await api(`/api/v1/migrations/${id}/${action}`, { method: "POST" });
      setMessage(action === "arm" ? "Migration armed for its scheduled cutover." : "Migration cancelled.");
      await migrations.reload();
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : `Could not ${action} migration`);
    }
  }

  if (resource.loading) return <Loading />;
  const success = message?.startsWith("Settings")
    || message?.startsWith("Migration")
    || message?.startsWith("SMTP");

  return (
    <>
      <PageHeader
        eyebrow="Client defaults"
        title="System settings"
        description="Only typed WireGuard options are accepted. Hooks and arbitrary configuration directives are intentionally unavailable."
      />
      {(resource.error || migrations.error || smtp.error || message) && (
        <Notice tone={success ? "success" : "danger"}>
          {resource.error || migrations.error || smtp.error || message}
        </Notice>
      )}

      <Card className="settings-card">
        <form className="form-grid" onSubmit={save}>
          <div className="form-section">
            <p className="eyebrow">Address management</p>
            <h2>VPN pool</h2>
            <p>In-place changes must expand to a containing supernet. Moving to a different subnet uses a scheduled migration.</p>
          </div>
          <Field label="IPv4 client pool" hint="The first usable address remains reserved for RouterOS compatibility.">
            <input required value={form.pool} onChange={(event) => setForm({ ...form, pool: event.target.value })} />
          </Field>
          <Field label="Default devices per user">
            <input required type="number" min="1" max="100" value={form.limit} onChange={(event) => setForm({ ...form, limit: event.target.value })} />
          </Field>
          <div className="form-section">
            <p className="eyebrow">Generated profiles</p>
            <h2>WireGuard options</h2>
          </div>
          <Field label="DNS servers" hint="Comma-separated IPv4 addresses">
            <input value={form.dns} onChange={(event) => setForm({ ...form, dns: event.target.value })} />
          </Field>
          <Field label="Search domains">
            <input value={form.domains} onChange={(event) => setForm({ ...form, domains: event.target.value })} />
          </Field>
          <Field label="MTU">
            <input type="number" min="576" max="9000" placeholder="Automatic" value={form.mtu} onChange={(event) => setForm({ ...form, mtu: event.target.value })} />
          </Field>
          <Field label="PersistentKeepalive">
            <input type="number" min="1" max="65535" placeholder="Disabled" value={form.keepalive} onChange={(event) => setForm({ ...form, keepalive: event.target.value })} />
          </Field>
          <div className="form-actions"><button className="button primary">Publish settings</button></div>
        </form>
      </Card>

      <Card className="settings-card migration-card">
        <div className="card-heading">
          <div>
            <p className="eyebrow">Coordinated cutover</p>
            <h2>Subnet migrations</h2>
            <p>WireMesh validates and preloads every gateway before the plan can be armed.</p>
          </div>
        </div>
        <form className="inline-form" onSubmit={createMigration}>
          <Field label="New IPv4 pool">
            <input required placeholder="10.80.0.0/20" value={migration.pool} onChange={(event) => setMigration({ ...migration, pool: event.target.value })} />
          </Field>
          <Field label="Effective local time">
            <input required type="datetime-local" value={migration.at} onChange={(event) => setMigration({ ...migration, at: event.target.value })} />
          </Field>
          <button className="button primary">Prepare migration</button>
        </form>
        {migrations.loading ? <Loading /> : !migrations.data?.length ? <Empty>No migration plans yet.</Empty> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Pool change</th><th>Cutover</th><th>Readiness</th><th>Status</th><th>Action</th></tr></thead>
              <tbody>{migrations.data.map((item) => (
                <tr key={item.id}>
                  <td><strong>{item.old_pool}</strong><br /><span className="muted">to {item.new_pool} · {item.affected_devices} devices</span></td>
                  <td>{formatDate(item.effective_at)}</td>
                  <td>{item.prepared_gateways}/{item.total_gateways} gateways</td>
                  <td><Status tone={item.status === "applied" ? "good" : item.status === "armed" || item.status === "preparing" ? "warn" : item.status === "failed" ? "bad" : "neutral"}>{item.status}</Status></td>
                  <td>{item.status === "preparing" && <div className="row-actions"><button type="button" className="button small primary" disabled={item.prepared_gateways !== item.total_gateways} onClick={() => migrationAction(item.id, "arm")}>Arm</button><button type="button" className="button small ghost" onClick={() => migrationAction(item.id, "cancel")}>Cancel</button></div>}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </Card>

      <Card className="settings-card migration-card">
        <form className="form-grid" onSubmit={saveMail}>
          <div className="form-section">
            <p className="eyebrow">Notifications</p>
            <h2>SMTP delivery</h2>
            <p>Credentials are encrypted under the external master key. Failed jobs retry with exponential backoff.</p>
          </div>
          <label className="check-row"><input type="checkbox" checked={mail.enabled} onChange={(event) => setMail({ ...mail, enabled: event.target.checked })} /> Enable email delivery</label>
          <div />
          <Field label="SMTP host"><input required value={mail.host} onChange={(event) => setMail({ ...mail, host: event.target.value })} /></Field>
          <Field label="Port"><input required type="number" min="1" max="65535" value={mail.port} onChange={(event) => setMail({ ...mail, port: event.target.value })} /></Field>
          <Field label="Transport security"><select value={mail.security} onChange={(event) => setMail({ ...mail, security: event.target.value as "start_tls" | "tls" })}><option value="start_tls">Required STARTTLS</option><option value="tls">Implicit TLS</option></select></Field>
          <Field label="Username"><input autoComplete="off" value={mail.username} onChange={(event) => setMail({ ...mail, username: event.target.value })} /></Field>
          <Field label="Password" hint={smtp.data?.has_password ? "Leave empty to retain the stored password." : undefined}><input type="password" autoComplete="new-password" value={mail.password} onChange={(event) => setMail({ ...mail, password: event.target.value })} /></Field>
          <Field label="From address"><input required type="email" placeholder="WireMesh <vpn@example.org>" value={mail.from} onChange={(event) => setMail({ ...mail, from: event.target.value })} /></Field>
          <Field label="Public WireMesh URL"><input required type="url" placeholder="https://vpn.example.org" value={mail.baseUrl} onChange={(event) => setMail({ ...mail, baseUrl: event.target.value })} /></Field>
          <div className="form-actions"><button className="button primary">Save SMTP settings</button></div>
        </form>
      </Card>
    </>
  );
}
