import { Card, Loading, Notice, PageHeader, Status } from "../components/ui";
import { useResource } from "../lib/hooks";
import type { Dashboard as DashboardData, Site } from "../types";

export default function Dashboard() {
  const dashboard = useResource<DashboardData>("/api/v1/dashboard");
  const sites = useResource<Site[]>("/api/v1/sites");
  if (dashboard.loading || !dashboard.data) return <Loading />;
  if (dashboard.error) return <Notice tone="danger">{dashboard.error}</Notice>;
  const value = dashboard.data;
  return (
    <>
      <PageHeader
        eyebrow="Network posture"
        title="Everything at a glance"
        description="Live control-plane health, address capacity, and gateway convergence."
        action={<Status tone={value.gateways_stale ? "warn" : "good"}>{value.gateways_stale ? `${value.gateways_stale} gateway stale` : "All gateways current"}</Status>}
      />
      <div className="metric-grid">
        <Card><span className="metric-label">People</span><strong className="metric-value">{value.users.toLocaleString()}</strong><small>managed identities</small></Card>
        <Card><span className="metric-label">Devices</span><strong className="metric-value">{value.devices.toLocaleString()}</strong><small>active and retained</small></Card>
        <Card><span className="metric-label">Sites</span><strong className="metric-value">{value.sites}</strong><small>protected networks</small></Card>
        <Card className="accent-card"><span className="metric-label">Online gateways</span><strong className="metric-value">{value.gateways_online}</strong><small>seen within 45 seconds</small></Card>
      </div>
      <div className="dashboard-grid">
        <Card>
          <div className="card-heading"><div><p className="eyebrow">Address pool</p><h2>{value.client_pool}</h2></div><strong>{value.pool_usage_percent.toFixed(1)}%</strong></div>
          <div className="capacity-bar" aria-label={`${value.pool_usage_percent.toFixed(1)} percent used`}><span style={{ width: `${Math.min(value.pool_usage_percent, 100)}%` }} /></div>
          <div className="capacity-legend">
            <span><i className="dot allocated" />{value.pool_allocated.toLocaleString()} allocated</span>
            <span><i className="dot quarantined" />{value.pool_quarantined.toLocaleString()} quarantined</span>
            <span>{value.pool_capacity.toLocaleString()} usable</span>
          </div>
          <p className="subtle-copy">The network, broadcast, and first usable address are reserved. Quarantined leases are released only after every affected gateway confirms removal.</p>
        </Card>
        <Card>
          <div className="card-heading"><div><p className="eyebrow">Convergence</p><h2>Gateway revisions</h2></div></div>
          {sites.data?.length ? (
            <div className="gateway-list">
              {sites.data.map((site) => {
                const current = site.desired_revision === site.applied_revision;
                return <div key={site.id}><span className={`gateway-dot ${current ? "online" : "pending"}`} /><div><strong>{site.name}</strong><small>{site.endpoint ?? "Waiting for gateway facts"}</small></div><span className="revision">r{site.applied_revision} / r{site.desired_revision}</span></div>;
              })}
            </div>
          ) : <div className="empty compact">Add a site and agent to begin.</div>}
        </Card>
      </div>
    </>
  );
}
