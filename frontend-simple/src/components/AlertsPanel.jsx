import React, { useEffect, useState } from "react";

// Live ML alerts: polls the scorer's /alerts (model-flagged windows), not raw log volume.
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

const SEV_COLOR = { critical: "#dc3545", high: "#fd7e14", medium: "#ffc107", none: "#666" };

export default function AlertsPanel() {
  const [alerts, setAlerts] = useState([]);
  const [online, setOnline] = useState(true);

  useEffect(() => {
    let active = true;
    async function poll() {
      try {
        const res = await fetch(`${API_BASE}/alerts?limit=50`);
        if (!res.ok) throw new Error("bad status");
        const j = await res.json();
        if (active) { setAlerts(j.alerts || []); setOnline(true); }
      } catch {
        if (active) setOnline(false);
      }
    }
    poll();
    const id = setInterval(poll, 5000);
    return () => { active = false; clearInterval(id); };
  }, []);

  return (
    <div style={{ margin: "20px 10px" }}>
      <h3 style={{ color: "#ccc" }}>
        Model Alerts {online ? `(${alerts.length})` : <span style={{ color: "#dc3545" }}>— scorer offline</span>}
      </h3>
      <div className="alerts-list">
        {alerts.map((a, i) => (
          <div key={i} style={{
            display: "flex", gap: 15, alignItems: "center", padding: "8px 10px",
            borderLeft: `4px solid ${SEV_COLOR[a.severity] || "#666"}`,
            background: "#1a1a1a", marginBottom: 4, fontFamily: "monospace", fontSize: "0.85rem",
          }}>
            <span style={{ color: SEV_COLOR[a.severity], fontWeight: "bold", minWidth: 70 }}>
              {(a.severity || "").toUpperCase()}
            </span>
            <span style={{ color: "#00d0ff", minWidth: 120 }}>{a.src_ip}</span>
            <span style={{ color: "#888", minWidth: 50 }}>{a.window}</span>
            <span style={{ color: "#eee" }}>score {a.score} · {a.events} events</span>
            {a.model_kind === "isolation_forest" && (
              <span style={{ color: "#666" }} title="Unsupervised — no labelled data yet">(anomaly)</span>
            )}
          </div>
        ))}
        {online && alerts.length === 0 && (
          <div style={{ padding: 20, color: "#666", textAlign: "center" }}>No model alerts yet.</div>
        )}
      </div>
    </div>
  );
}
