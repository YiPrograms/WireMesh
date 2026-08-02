import { useState, type FormEvent } from "react";
import { Card, Empty, Field, Loading, Notice, PageHeader, Status } from "../components/ui";
import { api, json } from "../lib/api";
import { useResource } from "../lib/hooks";
import type { Group, GroupMember, User } from "../types";

export default function Groups() {
  const groups = useResource<Group[]>("/api/v1/groups");
  const users = useResource<User[]>("/api/v1/users");
  const [selected, setSelected] = useState<Group | null>(null);
  const [members, setMembers] = useState<GroupMember[]>([]);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function select(group: Group) { setSelected(group); setMembers(await api(`/api/v1/groups/${group.id}/members`)); }
  async function create(event: FormEvent) { event.preventDefault(); try { await api("/api/v1/groups", json("POST", { name })); setName(""); await groups.reload(); } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not create group"); } }
  async function add(userId: string) { if (!selected || !userId) return; await api(`/api/v1/groups/${selected.id}/members`, json("POST", { user_id: userId })); await select(selected); await groups.reload(); }
  async function remove(userId: string) { if (!selected) return; try { await api(`/api/v1/groups/${selected.id}/members/${userId}`, { method: "DELETE" }); await select(selected); await groups.reload(); } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not remove membership"); } }

  if (groups.loading) return <Loading />;
  return <>
    <PageHeader eyebrow="Authorization" title="Groups" description="Same-name groups merge across local, LDAP, and OIDC sources. Provenance stays visible on every membership." />
    {(groups.error || error) && <Notice tone="danger">{groups.error || error}</Notice>}
    <div className="split-view">
      <Card><form className="quick-create" onSubmit={create}><input aria-label="New group name" placeholder="New canonical group" required value={name} onChange={(e) => setName(e.target.value)} /><button className="button primary">Add</button></form><div className="selection-list">{groups.data?.map((group) => <button className={selected?.id === group.id ? "selected" : ""} key={group.id} onClick={() => select(group)}><span><strong>{group.display_name}</strong><small>{group.normalized_name}</small></span><span className="count">{group.members}</span></button>)}</div></Card>
      <Card>{selected ? <><div className="card-heading"><div><p className="eyebrow">Membership</p><h2>{selected.display_name}</h2></div></div><Field label="Add local member"><select defaultValue="" onChange={(e) => { void add(e.target.value); e.target.value = ""; }}><option value="" disabled>Select a person…</option>{users.data?.filter((user) => !members.some((member) => member.user_id === user.id)).map((user) => <option value={user.id} key={user.id}>{user.name} · {user.email}</option>)}</select></Field><div className="member-list">{members.map((member) => <div key={member.user_id}><span className="avatar small">{member.name[0]?.toUpperCase()}</span><span><strong>{member.name}</strong><small>{member.email}</small></span><span className="source-pills">{member.sources.map((source) => <Status key={source} tone={source === "local" ? "neutral" : source.startsWith("ldap:") ? "good" : "warn"}>{source.toUpperCase()}</Status>)}</span>{member.sources.includes("local") && <button className="icon-button" aria-label={`Remove ${member.name}`} onClick={() => remove(member.user_id)}>×</button>}</div>)}</div></> : <Empty>Select a group to inspect source provenance and local members.</Empty>}</Card>
    </div>
  </>;
}
