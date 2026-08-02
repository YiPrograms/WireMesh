import type { ReactNode } from "react";
import type { AuthUser } from "../types";

export type Page =
  | "dashboard"
  | "devices"
  | "users"
  | "groups"
  | "sites"
  | "agents"
  | "identity"
  | "audit"
  | "settings";

const adminNavigation: Array<[Page, string, string]> = [
  ["dashboard", "Overview", "⌁"],
  ["devices", "My devices", "▣"],
  ["users", "People", "◎"],
  ["groups", "Groups", "◉"],
  ["sites", "Sites & policy", "◇"],
  ["agents", "Gateway agents", "↗"],
  ["identity", "Identity", "⊚"],
  ["audit", "Audit trail", "≡"],
  ["settings", "Settings", "⚙"],
];

export default function Layout({
  user,
  page,
  onPage,
  onLogout,
  children,
}: {
  user: AuthUser;
  page: Page;
  onPage: (page: Page) => void;
  onLogout: () => void;
  children: ReactNode;
}) {
  const navigation = user.is_admin
    ? adminNavigation
    : ([["devices", "My devices", "▣"]] as Array<[Page, string, string]>);
  return (
    <div className="shell">
      <aside className="sidebar">
        <button className="brand" onClick={() => onPage(user.is_admin ? "dashboard" : "devices")}>
          <span className="brand-mark">W</span>
          <span>
            <strong>WireMesh</strong>
            <small>Private access plane</small>
          </span>
        </button>
        <nav aria-label="Primary navigation">
          {navigation.map(([key, label, icon]) => (
            <button
              key={key}
              className={page === key ? "active" : ""}
              onClick={() => onPage(key)}
            >
              <span className="nav-icon">{icon}</span>
              {label}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="avatar">{user.name.slice(0, 1).toUpperCase()}</div>
          <div className="identity-summary">
            <strong>{user.name}</strong>
            <span>{user.is_admin ? "Administrator" : user.email}</span>
          </div>
          <button className="icon-button" onClick={onLogout} title="Sign out" aria-label="Sign out">
            ↪
          </button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
