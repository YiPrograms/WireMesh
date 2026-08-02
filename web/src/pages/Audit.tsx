import { Card, Empty, Loading, Notice, PageHeader, Status, formatDate } from "../components/ui";
import { useResource } from "../lib/hooks";
import type { AuditEvent } from "../types";

export default function Audit() {
  const resource = useResource<AuditEvent[]>("/api/v1/audit?limit=250");
  if (resource.loading) return <Loading />;
  return <><PageHeader eyebrow="Permanent record" title="Audit trail" description="Control-plane changes are append-only and retained. WireMesh does not store packet or connection logs." />{resource.error && <Notice tone="danger">{resource.error}</Notice>}<Card className="table-card">{resource.data?.length ? <div className="table-scroll"><table><thead><tr><th>Time</th><th>Action</th><th>Object</th><th>Actor</th><th>Outcome</th></tr></thead><tbody>{resource.data.map((event) => <tr key={event.id}><td>{formatDate(event.occurred_at)}</td><td><strong>{event.action}</strong></td><td>{event.object_kind}<small className="block mono">{event.object_id?.slice(0, 13) ?? "—"}</small></td><td>{event.actor_kind}</td><td><Status tone={event.outcome === "success" ? "good" : "bad"}>{event.outcome}</Status></td></tr>)}</tbody></table></div> : <Empty>No audit events recorded yet.</Empty>}</Card></>;
}
