import type { BenchmarkResult } from "../types";

// Log-log chart of MEASURED benchmark points only. No interpolation beyond
// the measured points, no projected values.

interface Props {
  results: BenchmarkResult[];
  selected: number | null;
}

const W = 720;
const H = 300;
const PAD = { left: 62, right: 150, top: 18, bottom: 40 };
const X_MIN = 100;
const X_MAX = 1_000_000;

function compact(n: number): string {
  if (n >= 1e9) return `${n / 1e9}B`;
  if (n >= 1e6) return `${n / 1e6}M`;
  if (n >= 1e3) return `${n / 1e3}K`;
  return String(n);
}

export function ScalingChart({ results, selected }: Props) {
  const points = [...results].sort((a, b) => a.raw_event_count - b.raw_event_count);
  const yValues = points.flatMap((r) => [r.estimated_raw_context_tokens, r.estimated_context_tokens]);
  const yMin = 1_000;
  const yMax = Math.max(1e6, ...yValues) * 1.5;
  const lx = (v: number) =>
    PAD.left + ((Math.log10(v) - Math.log10(X_MIN)) / (Math.log10(X_MAX) - Math.log10(X_MIN))) * (W - PAD.left - PAD.right);
  const ly = (v: number) =>
    PAD.top + (1 - (Math.log10(Math.max(v, yMin)) - Math.log10(yMin)) / (Math.log10(yMax) - Math.log10(yMin))) * (H - PAD.top - PAD.bottom);

  const xTicks = [100, 1_000, 10_000, 100_000, 1_000_000];
  const yTicks: number[] = [];
  for (let v = yMin; v <= yMax; v *= 10) yTicks.push(v);

  const line = (key: "estimated_raw_context_tokens" | "estimated_context_tokens") =>
    points.map((r, i) => `${i ? "L" : "M"}${lx(r.raw_event_count).toFixed(1)},${ly(r[key]).toFixed(1)}`).join(" ");
  const last = points[points.length - 1];

  return (
    <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img"
      aria-label="Estimated tokens versus raw event count, log-log, measured points only">
      {yTicks.map((v) => (
        <g key={`y${v}`}>
          <line x1={PAD.left} x2={W - PAD.right} y1={ly(v)} y2={ly(v)} className="grid" />
          <text x={PAD.left - 8} y={ly(v) + 4} className="tick" textAnchor="end">{compact(v)}</text>
        </g>
      ))}
      {xTicks.map((v) => (
        <g key={`x${v}`}>
          <line x1={lx(v)} x2={lx(v)} y1={PAD.top} y2={H - PAD.bottom} className="grid" />
          <text x={lx(v)} y={H - PAD.bottom + 16} className="tick" textAnchor="middle">{compact(v)}</text>
        </g>
      ))}
      <text x={(PAD.left + W - PAD.right) / 2} y={H - 6} className="axis" textAnchor="middle">RAW EVENTS (log)</text>
      <text x={14} y={(PAD.top + H - PAD.bottom) / 2} className="axis" textAnchor="middle"
        transform={`rotate(-90 14 ${(PAD.top + H - PAD.bottom) / 2})`}>EST. TOKENS (log)</text>

      {selected !== null && (
        <line x1={lx(selected)} x2={lx(selected)} y1={PAD.top} y2={H - PAD.bottom} className="cursor" />
      )}

      {points.length > 1 && <path d={line("estimated_raw_context_tokens")} className="series raw" />}
      {points.length > 1 && <path d={line("estimated_context_tokens")} className="series evidence" />}
      {points.map((r) => (
        <g key={r.scale}>
          <circle cx={lx(r.raw_event_count)} cy={ly(r.estimated_raw_context_tokens)} r={4} className="pt raw">
            <title>{`${r.raw_event_count.toLocaleString()} events → ${r.estimated_raw_context_tokens.toLocaleString()} raw-context tokens (estimate, not sent)`}</title>
          </circle>
          <circle cx={lx(r.raw_event_count)} cy={ly(r.estimated_context_tokens)} r={4} className="pt evidence">
            <title>{`${r.raw_event_count.toLocaleString()} events → ${r.estimated_context_tokens.toLocaleString()} evidence-context tokens`}</title>
          </circle>
        </g>
      ))}
      {last && (
        <>
          <text x={lx(last.raw_event_count) + 10} y={ly(last.estimated_raw_context_tokens) + 4} className="label raw">
            Naive raw baseline
          </text>
          <text x={lx(last.raw_event_count) + 10} y={ly(last.estimated_raw_context_tokens) + 18} className="label raw sub">
            estimated · not sent
          </text>
          <text x={lx(last.raw_event_count) + 10} y={ly(last.estimated_context_tokens) + 4} className="label evidence">
            Evidence context
          </text>
        </>
      )}
      {!points.length && (
        <text x={(PAD.left + W - PAD.right) / 2} y={H / 2} className="axis" textAnchor="middle">
          No measured points yet. Run the benchmark.
        </text>
      )}
    </svg>
  );
}
