import { useEffect, useState } from "react";
import Layout, { type Page } from "./components/Layout";
import { Loading } from "./components/ui";
import { api, ApiError } from "./lib/api";
import type { AuthUser } from "./types";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Users from "./pages/Users";
import Groups from "./pages/Groups";
import Sites from "./pages/Sites";
import Agents from "./pages/Agents";
import Identity from "./pages/Identity";
import Audit from "./pages/Audit";
import Settings from "./pages/Settings";
import Devices from "./pages/Devices";

function pageFromHash(admin: boolean): Page {
  const value = window.location.hash.slice(1) as Page;
  const adminPages: Page[] = ["dashboard", "devices", "users", "groups", "sites", "agents", "identity", "audit", "settings"];
  if (admin && adminPages.includes(value)) return value;
  return admin ? "dashboard" : "devices";
}

export default function App() {
  const [user, setUser] = useState<AuthUser | null | undefined>(undefined);
  const [page, setPage] = useState<Page>("dashboard");
  useEffect(() => { api<AuthUser>("/api/v1/auth/me").then((value) => { setUser(value); setPage(pageFromHash(value.is_admin)); }).catch((error) => { if (error instanceof ApiError && error.status === 401) setUser(null); else setUser(null); }); }, []);
  useEffect(() => { const listener = () => user && setPage(pageFromHash(user.is_admin)); window.addEventListener("hashchange", listener); return () => window.removeEventListener("hashchange", listener); }, [user]);
  if (user === undefined) return <div className="full-loading"><Loading /></div>;
  if (!user) return <Login onAuthenticated={(value) => { setUser(value); setPage(value.is_admin ? "dashboard" : "devices"); }} />;
  function navigate(next: Page) { window.location.hash = next; setPage(next); }
  async function logout() { await api("/api/v1/auth/logout", { method: "POST" }); setUser(null); window.location.hash = ""; }
  const content = page === "dashboard" ? <Dashboard /> : page === "users" ? <Users /> : page === "groups" ? <Groups /> : page === "sites" ? <Sites /> : page === "agents" ? <Agents /> : page === "identity" ? <Identity /> : page === "audit" ? <Audit /> : page === "settings" ? <Settings /> : <Devices user={user} />;
  return <Layout user={user} page={page} onPage={navigate} onLogout={logout}>{content}</Layout>;
}
