import { useState } from "react";
import type { AuditRecord } from "@/lib/verifyAudit";

const FIELDS: (keyof AuditRecord)[] = ["seq", "tool", "ts", "exit_code", "stdout_sha256", "prev_hash", "hash"];

export function RecordInspector({
  records, selected, onSelect, citations, brokenSeq, onEdit, onTamper,
}: {
  records: AuditRecord[];
  selected: number;
  onSelect: (seq: number) => void;
  citations: Record<string, string[]>;
  brokenSeq?: number;
  onEdit: (seq: number, field: keyof AuditRecord, value: string) => void;
  onTamper: (seq: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const rec = records[selected] ?? records[0];
  const cites = citations[rec.hash] ?? [];

  return (
    <div className="mt-4">
      <button onClick={() => setOpen((v) => !v)} className="text-sky-400 hover:underline">
        {open ? "▾" : "▸"} open the full inspector — all {records.length} records, click any field to edit it
      </button>
      {open && (
        <div className="mt-3 grid gap-3 md:grid-cols-[210px_1fr]">
          <ul className="space-y-1">
            {records.map((r, i) => {
              const broken = brokenSeq !== undefined && i >= brokenSeq;
              return (
                <li key={r.seq}>
                  <button
                    onClick={() => onSelect(r.seq)}
                    className={`flex w-full justify-between rounded-md border px-2 py-1 ${
                      selected === r.seq ? "border-sky-600" : "border-neutral-800"
                    } ${broken ? "text-red-400" : "text-neutral-300"}`}
                  >
                    <span>seq{r.seq} {r.tool}</span>
                    <span>{broken ? "✗" : "⛓"}</span>
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="space-y-1">
            {FIELDS.map((f) => (
              <div key={f} className="flex gap-2">
                <span className="w-28 shrink-0 text-neutral-500">{f}</span>
                <span
                  contentEditable={f !== "seq"}
                  suppressContentEditableWarning
                  onBlur={(e) => onEdit(rec.seq, f, e.currentTarget.textContent ?? "")}
                  className="break-all text-neutral-200 outline-none focus:bg-neutral-900"
                >
                  {String(rec[f])}
                </span>
              </div>
            ))}
            {cites.length > 0 && (
              <p className="mt-2 rounded-md border border-dashed border-emerald-800 p-2 text-xs text-emerald-400">
                A finding&apos;s tool_call_id IS this hash. Findings citing it: {cites.join("; ")}
              </p>
            )}
            <button onClick={() => onTamper(rec.seq)} className="mt-2 text-amber-400 hover:underline">
              ⚠ flip a byte in this record
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
