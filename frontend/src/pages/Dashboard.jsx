import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import {
  getMe, getHealth, getDashboardSummary, getAttackDistribution,
  getAlerts, getBlockedSources, getPreventionActions, getMLModel,
  generateSimulation, runDetection,
} from "../services/api";
import { useLiveEvents } from "../hooks/useLiveEvents";

const SCENARIOS = ["BENIGN", "HIGH_CONNECTION_RATE", "BRUTE_FORCE", "ANOMALY", "BOT_ACTIVITY"];

export default function Dashboard() {
  const [user, setUser] = useState(null);
  const [health, setHealth] = useState(null);
  const [summary, setSummary] = useState(null);
  const [attackDist, setAttackDist] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [blocked, setBlocked] = useState([]);
  const [actions, setActions] = useState([]);
  const [mlModel, setMlModel] = useState(null);
  const [scenario, setScenario] = useState("HIGH_CONNECTION_RATE");
  const [count, setCount] = useState(10);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const { messages: liveEvents, connected } = useLiveEvents();

  const loadAll = async () => {
    try {
      const [meRes, healthRes, summaryRes, attackRes, alertsRes, blockedRes, actionsRes] =
        await Promise.all([
          getMe(), getHealth(), getDashboardSummary(), getAttackDistribution(),
          getAlerts({ limit: 10 }), getBlockedSources(), getPreventionActions(),
        ]);
      setUser(meRes.data);
      setHealth(healthRes.data);
      setSummary(summaryRes.data);
      setAttackDist(attackRes.data);
      setAlerts(alertsRes.data);
      setBlocked(blockedRes.data);
      setActions(actionsRes.data.slice(0, 10));

      try {
        const mlRes = await getMLModel();
        setMlModel(mlRes.data);
      } catch {
        setMlModel(null); // model not trained yet - handled gracefully
      }
    } catch (err) {
      localStorage.removeItem("aiidps_token");
      navigate("/");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
    const interval = setInterval(loadAll, 8000); // periodic refresh as a fallback to WebSocket push
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleGenerate = async () => {
    setBusy(true);
    try {
      await generateSimulation(scenario, Number(count));
      await runDetection();
      await loadAll();
    } finally {
      setBusy(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("aiidps_token");
    navigate("/");
  };

  if (loading) return <div style={styles.loading}>Loading...</div>;

  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <h1 style={styles.logo}>AI-IDPS</h1>
        <div>
          <span style={styles.userInfo}>{user?.name} ({user?.role})</span>
          <button style={styles.logoutBtn} onClick={handleLogout}>Logout</button>
        </div>
      </header>

      <main style={styles.main}>
        {/* System Status */}
        <Section title="System Status">
          <div style={styles.row}>
            <StatusPill label="Backend" ok={health?.backend === "ok"} />
            <StatusPill label="PostgreSQL" ok={health?.postgres === "ok"} />
            <StatusPill label="Redis" ok={health?.redis === "ok"} />
            <StatusPill label="Live Feed (WebSocket)" ok={connected} />
          </div>
        </Section>

        {/* Demo Controls */}
        <Section title="Generate Demo Traffic">
          <div style={styles.row}>
            <select style={styles.select} value={scenario} onChange={(e) => setScenario(e.target.value)}>
              {SCENARIOS.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <input
              style={styles.numberInput}
              type="number"
              min="1"
              max="100"
              value={count}
              onChange={(e) => setCount(e.target.value)}
            />
            <button style={styles.actionBtn} onClick={handleGenerate} disabled={busy}>
              {busy ? "Running..." : "Generate + Detect"}
            </button>
          </div>
        </Section>

        {/* Stats Cards */}
        <Section title="Statistics">
          <div style={styles.row}>
            <StatCard label="Total Events" value={summary?.total_events ?? 0} />
            <StatCard label="Threats Detected" value={summary?.threats_detected ?? 0} />
            <StatCard label="Critical Alerts" value={summary?.critical_alerts ?? 0} color="#ff4d4f" />
            <StatCard label="Blocked Sources" value={summary?.blocked_sources ?? 0} color="#ffa940" />
          </div>
        </Section>

        {/* Threat Distribution Chart */}
        <Section title="Threat Distribution">
          {attackDist.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={attackDist}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                <XAxis dataKey="attack_type" stroke="#c9d1d9" />
                <YAxis stroke="#c9d1d9" allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: "#161b22", border: "1px solid #30363d" }} />
                <Bar dataKey="count" fill="#00ff9d" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p style={styles.placeholder}>No classified events yet.</p>
          )}
        </Section>

        {/* Live Events (WebSocket) */}
        <Section title="Live Events">
          {liveEvents.length === 0 ? (
            <p style={styles.placeholder}>Waiting for live events... generate traffic above.</p>
          ) : (
            <div style={styles.scrollBox}>
              {liveEvents.map((msg, i) => (
                <div key={i} style={styles.liveItem}>
                  <span style={{ color: msg.type === "prevention_action" ? "#ffa940" : "#00ff9d" }}>
                    {msg.type === "prevention_action" ? "🛡️" : "🚨"}
                  </span>{" "}
                  {msg.type === "new_alert"
                    ? `${msg.severity} - ${msg.attack_type}: ${msg.message}`
                    : `${msg.action} on ${msg.target} (event #${msg.event_id})`}
                </div>
              ))}
            </div>
          )}
        </Section>

        {/* Recent Alerts */}
        <Section title="Recent Alerts">
          {alerts.length === 0 ? (
            <p style={styles.placeholder}>No alerts yet.</p>
          ) : (
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Time</th>
                  <th style={styles.th}>Type</th>
                  <th style={styles.th}>Severity</th>
                  <th style={styles.th}>Status</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td style={styles.td}>{new Date(a.created_at).toLocaleTimeString()}</td>
                    <td style={styles.td}>{a.attack_type}</td>
                    <td style={{ ...styles.td, color: severityColor(a.severity) }}>{a.severity}</td>
                    <td style={styles.td}>{a.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>

        {/* Prevention */}
        <Section title="Prevention">
          <div style={styles.twoCol}>
            <div>
              <h4 style={styles.subheading}>Blocked Sources ({blocked.length})</h4>
              {blocked.slice(0, 8).map((b) => (
                <div key={b.id} style={styles.listItem}>{b.source_identifier} — {b.severity}</div>
              ))}
            </div>
            <div>
              <h4 style={styles.subheading}>Recent Actions</h4>
              {actions.slice(0, 8).map((a) => (
                <div key={a.id} style={styles.listItem}>{a.action} → {a.target}</div>
              ))}
            </div>
          </div>
        </Section>

        {/* ML Model */}
        <Section title="ML Model">
          {mlModel ? (
            <div style={styles.row}>
              <StatCard label="Algorithm" value={mlModel.algorithm} small />
              <StatCard label="Accuracy" value={`${(mlModel.accuracy * 100).toFixed(1)}%`} small />
              <StatCard label="Precision" value={`${(mlModel.precision * 100).toFixed(1)}%`} small />
              <StatCard label="Recall" value={`${(mlModel.recall * 100).toFixed(1)}%`} small />
              <StatCard label="F1 Score" value={`${(mlModel.f1_score * 100).toFixed(1)}%`} small />
            </div>
          ) : (
            <p style={styles.placeholder}>No trained model found.</p>
          )}
        </Section>
      </main>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section style={styles.section}>
      <h2 style={styles.sectionTitle}>{title}</h2>
      {children}
    </section>
  );
}

function StatusPill({ label, ok }) {
  return (
    <div style={styles.pill}>
      <span style={{ color: ok ? "#00ff9d" : "#ff4d4f" }}>{ok ? "🟢" : "🔴"}</span> {label}
    </div>
  );
}

function StatCard({ label, value, color, small }) {
  return (
    <div style={{ ...styles.statCard, ...(small ? styles.statCardSmall : {}) }}>
      <div style={{ ...styles.statValue, color: color || "#00ff9d" }}>{value}</div>
      <div style={styles.statLabel}>{label}</div>
    </div>
  );
}

function severityColor(sev) {
  return { LOW: "#8b949e", MEDIUM: "#ffd666", HIGH: "#ffa940", CRITICAL: "#ff4d4f" }[sev] || "#c9d1d9";
}

const styles = {
  page: { minHeight: "100vh", backgroundColor: "#0d1117", color: "#c9d1d9", fontFamily: "Segoe UI, sans-serif" },
  header: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "1rem 2rem", borderBottom: "1px solid #30363d", position: "sticky", top: 0,
    backgroundColor: "#0d1117", zIndex: 10,
  },
  logo: { color: "#00ff9d", margin: 0 },
  userInfo: { marginRight: "1rem", fontSize: "0.9rem" },
  logoutBtn: {
    padding: "0.4rem 0.9rem", borderRadius: "6px", border: "1px solid #30363d",
    backgroundColor: "transparent", color: "#c9d1d9", cursor: "pointer",
  },
  main: { padding: "1.5rem 2rem", maxWidth: "1100px", margin: "0 auto" },
  section: { marginBottom: "2rem" },
  sectionTitle: { fontSize: "1.05rem", marginBottom: "0.8rem", color: "#c9d1d9" },
  row: { display: "flex", gap: "1rem", flexWrap: "wrap", alignItems: "center" },
  pill: { backgroundColor: "#161b22", padding: "0.6rem 1.2rem", borderRadius: "8px", border: "1px solid #30363d" },
  select: {
    backgroundColor: "#161b22", color: "#c9d1d9", border: "1px solid #30363d",
    borderRadius: "6px", padding: "0.5rem",
  },
  numberInput: {
    backgroundColor: "#161b22", color: "#c9d1d9", border: "1px solid #30363d",
    borderRadius: "6px", padding: "0.5rem", width: "70px",
  },
  actionBtn: {
    backgroundColor: "#00ff9d", color: "#0d1117", border: "none", borderRadius: "6px",
    padding: "0.5rem 1.2rem", fontWeight: "bold", cursor: "pointer",
  },
  statCard: {
    backgroundColor: "#161b22", border: "1px solid #30363d", borderRadius: "8px",
    padding: "1rem 1.5rem", minWidth: "140px",
  },
  statCardSmall: { minWidth: "110px", padding: "0.7rem 1rem" },
  statValue: { fontSize: "1.6rem", fontWeight: "bold" },
  statLabel: { fontSize: "0.8rem", color: "#8b949e", marginTop: "0.3rem" },
  placeholder: { color: "#8b949e" },
  scrollBox: { maxHeight: "220px", overflowY: "auto", backgroundColor: "#161b22", borderRadius: "8px", padding: "0.8rem", border: "1px solid #30363d" },
  liveItem: { padding: "0.4rem 0", fontSize: "0.85rem", borderBottom: "1px solid #21262d" },
  table: { width: "100%", borderCollapse: "collapse" },
  th: { textAlign: "left", padding: "0.5rem", borderBottom: "1px solid #30363d", color: "#8b949e", fontSize: "0.8rem" },
  td: { padding: "0.5rem", borderBottom: "1px solid #21262d", fontSize: "0.85rem" },
  twoCol: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2rem" },
  subheading: { fontSize: "0.9rem", color: "#8b949e", marginBottom: "0.5rem" },
  listItem: { fontSize: "0.85rem", padding: "0.3rem 0", borderBottom: "1px solid #21262d" },
  loading: {
    color: "#c9d1d9", backgroundColor: "#0d1117", minHeight: "100vh",
    display: "flex", alignItems: "center", justifyContent: "center",
  },
};
