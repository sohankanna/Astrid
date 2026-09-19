import { useEffect, useId, useRef, useState, type ReactNode } from "react";

/** Native modal semantics provide focus trapping, Escape and focus restoration. */
export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = ref.current!;
    const previous = document.activeElement as HTMLElement | null;
    dialog.showModal();
    return () => { dialog.close(); previous?.focus(); };
  }, []);
  return (
    <dialog ref={ref} className="detail-drawer" aria-labelledby={titleId} onCancel={(e) => { e.preventDefault(); onClose(); }}>
      <header className="drawer-head"><h2 id={titleId}>{title}</h2><button className="btn" onClick={onClose} autoFocus aria-label="Close details">Close ×</button></header>
      <div className="drawer-body">{children}</div>
    </dialog>
  );
}

export function Disclosure({ label, title = label, children }: { label: string; title?: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return <><button className="btn" aria-haspopup="dialog" onClick={() => setOpen(true)}>{label}</button>
    {open && <Drawer title={title} onClose={() => setOpen(false)}>{children}</Drawer>}</>;
}

export function Tabs<T extends string>({ id, tabs, value, onChange }: {
  id: string; tabs: readonly T[]; value: T; onChange: (value: T) => void;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  return <div className="detail-tabs" role="tablist" aria-label={id === "incident" ? "Incident investigation" : "Efficiency Lab"}>
    {tabs.map((tab, index) => <button key={tab} ref={(el) => { refs.current[index] = el; }} role="tab"
      id={`${id}-tab-${index}`} aria-controls={`${id}-panel-${index}`} aria-selected={value === tab}
      tabIndex={value === tab ? 0 : -1} onClick={() => onChange(tab)}
      onKeyDown={(e) => {
        const next = e.key === "ArrowRight" ? (index + 1) % tabs.length : e.key === "ArrowLeft" ? (index + tabs.length - 1) % tabs.length : e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : null;
        if (next !== null) { e.preventDefault(); onChange(tabs[next]); refs.current[next]?.focus(); }
      }}>{tab}</button>)}
  </div>;
}

export function TabPanel({ id, index, active, children }: { id: string; index: number; active: boolean; children: ReactNode }) {
  return <div role="tabpanel" id={`${id}-panel-${index}`} aria-labelledby={`${id}-tab-${index}`} hidden={!active} tabIndex={0}>{children}</div>;
}
