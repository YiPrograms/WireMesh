import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, json } from "../lib/api";
import type { AuthUser, LoginProvider } from "../types";
import { Field, Notice } from "../components/ui";

export default function Login({ onAuthenticated }: { onAuthenticated: (user: AuthUser) => void }) {
  const enrollment = useMemo(
    () => new URLSearchParams(window.location.search).get("enrollment"),
    [],
  );
  const reset = useMemo(
    () => new URLSearchParams(window.location.search).get("reset"),
    [],
  );
  const [mode, setMode] = useState<"local" | "ldap" | "enroll" | "reset">(reset ? "reset" : enrollment ? "enroll" : "local");
  const [providers, setProviders] = useState<LoginProvider[]>([]);
  const [providerId, setProviderId] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState(reset ?? enrollment ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { void api<LoginProvider[]>("/api/v1/auth/providers").then(setProviders).catch(() => setProviders([])); }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const user =
        mode === "local"
          ? await api<AuthUser>("/api/v1/auth/login/local", json("POST", { email, password }))
          : mode === "ldap"
            ? await api<AuthUser>("/api/v1/auth/login/ldap", json("POST", { provider_id: providerId, email, password }))
          : await api<AuthUser>(mode === "reset" ? "/api/v1/auth/reset" : "/api/v1/auth/enroll", json("POST", { token, password }));
      window.history.replaceState({}, "", window.location.pathname);
      onAuthenticated(user);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sign in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <section className="login-story">
        <div className="login-brand"><span>W</span> WireMesh</div>
        <div className="story-copy">
          <p className="eyebrow">Quietly connected</p>
          <h1>Private routes.<br />Clear control.</h1>
          <p>
            One profile for every site you are allowed to reach. Keys stay on your device;
            policy stays with your organization.
          </p>
        </div>
        <div className="mesh-art" aria-hidden="true">
          <i /><i /><i /><i /><i />
        </div>
        <small>IPv4 split tunnel · WireGuard · On premises</small>
      </section>
      <section className="login-panel">
        <form onSubmit={submit}>
          <p className="eyebrow">{mode === "enroll" ? "Account setup" : mode === "reset" ? "Account recovery" : "Welcome back"}</p>
          <h2>{mode === "enroll" ? "Create your local password" : mode === "reset" ? "Choose a new password" : "Sign in to WireMesh"}</h2>
          <p className="muted">
            {mode !== "enroll" && mode !== "reset"
              ? "Choose the identity realm your administrator assigned to you."
              : mode === "reset" ? "Reset links are single-use and expire after one hour." : "Enrollment links are single-use and expire after seven days."}
          </p>
          {error && <Notice tone="danger">{error}</Notice>}
          {mode !== "enroll" && mode !== "reset" ? (
            <Field label="Email address">
              <input type="email" required autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} />
            </Field>
          ) : (
            <Field label={mode === "reset" ? "Reset token" : "Enrollment token"}>
              <input required autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} />
            </Field>
          )}
          {mode === "ldap" && <Field label="LDAP realm"><select required value={providerId} onChange={(event) => setProviderId(event.target.value)}><option value="">Choose a directory…</option>{providers.filter((provider) => provider.kind === "ldap").map((provider) => <option value={provider.id} key={provider.id}>{provider.name}</option>)}</select></Field>}
          <Field label={mode === "enroll" || mode === "reset" ? "New password" : "Password"} hint={mode === "enroll" || mode === "reset" ? "Use at least 12 characters." : undefined}>
            <input type="password" required minLength={mode === "enroll" || mode === "reset" ? 12 : undefined} autoComplete={mode === "local" || mode === "ldap" ? "current-password" : "new-password"} value={password} onChange={(event) => setPassword(event.target.value)} />
          </Field>
          <button className="button primary wide" disabled={busy}>
            {busy ? "Please wait…" : mode === "enroll" ? "Finish enrollment" : mode === "reset" ? "Reset password" : "Sign in"}
          </button>
          <button className="text-button" type="button" onClick={() => setMode(mode === "enroll" || mode === "reset" ? "local" : "enroll")}>
            {mode !== "enroll" && mode !== "reset" ? "Use an enrollment token" : "Return to sign in"}
          </button>
          {mode !== "enroll" && mode !== "reset" && (
            <div className="realm-note">
              <strong>Choose a realm</strong>
              <div className="realm-buttons"><button type="button" className={mode === "local" ? "active" : ""} onClick={() => setMode("local")}>Local</button>{providers.filter((provider) => provider.kind === "ldap").length > 0 && <button type="button" className={mode === "ldap" ? "active" : ""} onClick={() => { setMode("ldap"); setProviderId(providers.find((provider) => provider.kind === "ldap")?.id ?? ""); }}>LDAP</button>}{providers.filter((provider) => provider.kind === "oidc").map((provider) => <a key={provider.id} href={`/api/v1/auth/oidc/${provider.id}/start`}>{provider.name}</a>)}</div>
              <span>Credentials are sent only to the realm you select; WireMesh never tries a password against multiple sources.</span>
            </div>
          )}
        </form>
      </section>
    </div>
  );
}
