import { useEffect, useState } from "react";
import type { Health } from "../types";

interface Props {
  health: Health | null;
  backendDown: boolean;
}

function Indicator({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`indicator ${ok ? "ok" : "down"}`}>
      <span className="dot" />
      {label}
    </span>
  );
}

export function TopBar({ health, backendDown }: Props) {
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
        <span className="brand-name">AI SOC COMMAND CENTER</span>
        <span className="env-tag">{health?.environment ?? "LOCAL / OFFLINE LAB"}</span>
      </div>
      <div className="indicators">
        <Indicator ok={up && !!health?.soc_online} label={up ? "SOC ONLINE" : "SOC OFFLINE"} />
        <Indicator ok={up && !!health?.siem.connected} label={up ? "SIEM CONNECTED" : "SIEM UNREACHABLE"} />
        <Indicator ok={up && !!health?.ai_analyst.ready} label={up ? "AI ANALYST READY" : "AI ANALYST UNAVAILABLE"} />
        <Indicator
          ok={up && !!health?.response_engine.armed}
          label={up ? `RESPONSE ENGINE ARMED · ${health?.response_engine.mode}` : "RESPONSE ENGINE OFFLINE"}
        />
      </div>
      <div className="clock">
        <span>{now.toISOString().slice(0, 10)}</span>
        <strong>{now.toISOString().slice(11, 19)} UTC</strong>
      </div>
    </header>
  );
}
