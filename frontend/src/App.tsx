import { useCallback, useEffect, useState } from "react";

type Alert = { id: number; ts: string; src_ip: string; dst_ip: string; dst_port: number | null; protocol: string; category: string; severity: string; confidence: number; method: string; description: string; action: string; source: string; status: string; notes: string };
type Status = { running: boolean; mode: string | null; packets: number; error: string | null; baselineReady: boolean };
type Me = { email: string; role: string; token: string };

async function api<T>(path: string, token: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const res = await fetch(`/api${path}`, { method: init?.method ?? "GET", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: init?.body ? JSON.stringify(init.body) : undefined });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof j.detail === "string" ? j.detail : "Request failed");
  return j;
}

function Login({ onDone }: { onDone: (m: Me) => void }) {
  const [reg, setReg] = useState(false); const [email, setEmail] = useState(""); const [password, setPw] = useState(""); const [err, setErr] = useState("");
  const go = async () => {
    const res = await fetch(`/api/auth/${reg ? "register" : "login"}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
    const j = await res.json();
    if (!res.ok) return setErr(typeof j.detail === "string" ? j.detail : "Check your email and password (8+ characters)");
    onDone(j);
  };
  return <div className="auth"><h2 style={{ margin: 0 }}>AI-IDS console</h2><small>The first account created becomes the administrator.</small>
    <input placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} /><input placeholder="Password" type="password" value={password} onChange={(e) => setPw(e.target.value)} />
    {err && <div className="err">{err}</div>}<button className="btn" onClick={go}>{reg ? "Create account" : "Log in"}</button>
    <button className="btn ghost" onClick={() => setReg(!reg)}>{reg ? "Have an account? Log in" : "Register"}</button></div>;
}

export default function App() {
  const [me, setMe] = useState<Me | null>(() => { const s = localStorage.getItem("ids_me"); return s ? JSON.parse(s) : null; });
  const [st, setSt] = useState<Status | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [sev, setSev] = useState(""); const [q, setQ] = useState("");
  const [err, setErr] = useState("");
  const [ifaces, setIfaces] = useState<string[]>([]); const [iface, setIface] = useState("");

  const refresh = useCallback(async () => {
    if (!me) return;
    try {
      setSt(await api<Status>("/network/status", me.token));
      const d = await api<{ total: number; items: Alert[] }>(`/detection/alerts?severity=${sev}&q=${encodeURIComponent(q)}`, me.token);
      setAlerts(d.items); setTotal(d.total);
    } catch (e) { if ((e as Error).message === "Not authenticated") { localStorage.removeItem("ids_me"); setMe(null); } }
  }, [me, sev, q]);

  useEffect(() => { refresh(); const t = setInterval(refresh, 3000); return () => clearInterval(t); }, [refresh]);
  useEffect(() => { // live push; polling above is the fallback
    if (!me) return;
    api<string[]>("/network/interfaces", me.token).then((i) => { setIfaces(i); setIface(i[0] ?? ""); }).catch(() => {});
    const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/alerts?token=${me.token}`);
    ws.onmessage = () => refresh();
    return () => ws.close();
  }, [me?.token]); // eslint-disable-line

  if (!me) return <Login onDone={(m) => { localStorage.setItem("ids_me", JSON.stringify(m)); setMe(m); }} />;
  const admin = me.role === "admin", canEdit = admin || me.role === "analyst";
  const run = async (path: string, body?: unknown) => { setErr(""); try { setSt(await api<Status>(path, me.token, { method: "POST", body })); } catch (e) { setErr((e as Error).message); } };
  const patch = (id: number, body: object) => api(`/detection/alerts/${id}`, me.token, { method: "PATCH", body }).then(refresh).catch((e) => setErr(e.message));
  const crit = alerts.filter((a) => a.severity === "critical").length;

  return (
    <>
      <header className="top"><b>AI-IDS</b>
        <span className="row"><small>{me.email} · {me.role}</small><button className="btn ghost" onClick={() => { localStorage.removeItem("ids_me"); setMe(null); }}>Log out</button></span></header>
      <main>
        {st?.mode === "simulation" && st.running && <div className="banner">Simulation mode: traffic is synthetic and every alert below from this run is labelled "simulation". This is not your network.</div>}
        <div className="cards">
          <div className="card"><b>{st?.packets ?? 0}</b><span>Packets analyzed</span></div>
          <div className="card"><b>{total}</b><span>Alerts (filtered)</span></div>
          <div className="card"><b>{crit}</b><span>Critical on this page</span></div>
          <div className="card"><b>{st?.running ? st.mode : "stopped"}</b><span>Monitor{st?.running ? (st.baselineReady ? " · ML baseline ready" : " · learning baseline") : ""}</span></div>
        </div>
        {admin && <div className="row">
          <button className="btn" disabled={st?.running} onClick={() => run("/network/monitor/start", { mode: "simulation" })}>Start simulation</button>
          <select value={iface} onChange={(e) => setIface(e.target.value)}>{ifaces.length === 0 && <option>No interfaces found</option>}{ifaces.map((i) => <option key={i}>{i}</option>)}</select>
          <button className="btn" disabled={st?.running || !iface} onClick={() => run("/network/monitor/start", { mode: "live", interface: iface })}>Start live capture</button>
          <button className="btn ghost" disabled={!st?.running} onClick={() => run("/network/monitor/stop")}>Stop</button>
          <small>Only monitor networks you are authorized to monitor. Live capture needs root/admin privileges.</small>
        </div>}
        {(err || st?.error) && <div className="err">{err || st?.error}</div>}
        <div className="row"><select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low", "informational"].map((s) => <option key={s}>{s}</option>)}</select>
          <input placeholder="Search by IP" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <div className="wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Source → Target</th><th>Method</th><th>Conf.</th><th>Details</th><th>Status</th></tr></thead><tbody>
          {alerts.length === 0 && <tr><td colSpan={8}><small>No alerts yet. Alerts appear only when the detection engines find something.</small></td></tr>}
          {alerts.map((a) => (
            <tr key={a.id}><td>{new Date(a.ts + "Z").toLocaleTimeString()}</td><td className={`sev ${a.severity}`}>{a.severity}</td><td>{a.category}<br /><small>{a.source}</small></td>
              <td>{a.src_ip} → {a.dst_ip}{a.dst_port ? `:${a.dst_port}` : ""}<br /><small>{a.protocol}</small></td><td>{a.method}</td><td>{Math.round(a.confidence * 100)}%</td>
              <td style={{ maxWidth: 380 }}>{a.description}<br /><small>Action: {a.action}</small>
                {canEdit && <><br /><input style={{ width: "100%", marginTop: 4 }} placeholder="Analyst notes (saves on leave)" defaultValue={a.notes} onBlur={(e) => e.target.value !== a.notes && patch(a.id, { notes: e.target.value })} /></>}</td>
              <td>{canEdit ? <select value={a.status} onChange={(e) => patch(a.id, { status: e.target.value })}><option>open</option><option>investigating</option><option>investigated</option></select> : a.status}</td></tr>
          ))}</tbody></table></div>
      </main>
    </>
  );
}
