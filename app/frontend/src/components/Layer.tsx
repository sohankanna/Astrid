/** Visual legend: which layer of the evidence hierarchy a panel belongs to. */
export function Layer({ kind }: { kind: "observed" | "correlated" | "ai" | "response" }) {
  const text = {
    observed: "OBSERVED · raw telemetry",
    correlated: "CORRELATED · deterministic engine",
    ai: "AI ASSESSMENT · advisory",
    response: "RECOMMENDED RESPONSE · human-gated",
  }[kind];
  return <span className={`layer layer-${kind}`}>{text}</span>;
}
