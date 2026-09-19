import { useEffect, useState } from "react";
import type { Health } from "../types";

interface Props {
  health: Health | null;
  backendDown: boolean;
  view: "console" | "lab";
  onView: (view: "console" | "lab") => void;
}

function Indicator({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`indicator ${ok ? "ok" : "down"}`}>
      <span className="dot" />
      {label}
    </span>
  );
}

export function TopBar({ health, backendDown, view, onView }: Props) {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const up = !backendDown && health !== null;
  return (
    <header className="topbar">
      <div className="brand">
        <span className="brand-mark">◆</span>
        <span className="brand-name">AI SOC Command Center</span>
        <span className="env-tag">{health?.environment ?? "LOCAL / OFFLINE LAB"}</span>
      </div>
      <nav className="views">
        <button className={view === "console" ? "active" : ""} onClick={() => onView("console")}>SOC Console</button>
        <button className={view === "lab" ? "active" : ""} onClick={() => onView("lab")}>AI Efficiency Lab</button>
      </nav>
      <div className="indicators">
        <Indicator ok={up && !!health?.soc_online} label={up ? "SOC online" : "SOC offline"} />
        <Indicator ok={up && !!health?.siem.connected} label={up ? "SIEM connected" : "SIEM unreachable"} />
        <Indicator ok={up && !!health?.ai_analyst.ready} label={up ? "AI analyst ready" : "AI analyst unavailable"} />
        <Indicator
          ok={up && !!health?.response_engine.armed}
          label={up ? `Response engine armed · ${health?.response_engine.mode}` : "Response engine offline"}
        />
      </div>
      <div className="clock">
        <span>{now.toISOString().slice(0, 10)}</span>
        <strong>{now.toISOString().slice(11, 19)} UTC</strong>
      </div>
    </header>
  );
}
