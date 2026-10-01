"use client";

import { useState } from "react";
import type { Finding, Severity } from "@/lib/types";
import { baseName } from "@/lib/format";
import { EvidenceViewer } from "./EvidenceViewer";
import { Badge, Card, CardHeader, Icon } from "./ui";

const SEV: Record<Severity, "danger" | "warn" | "neutral" | "brand"> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "neutral",
  info: "brand",
};

export function FindingsTable({ findings, rootIds }: { findings: Finding[]; rootIds: string[] }) {
  const [filter, setFilter] = useState<"all" | "cause" | "symptom">("all");
  const [open, setOpen] = useState<string | null>(rootIds[0] ?? findings[0]?.id ?? null);
  const shown = findings.filter((f) => filter === "all" || f.role === filter);

  return (
    <Card>
      <CardHeader
        title="Findings"
        sub="Ranked with causes first. A cause explains why it broke; a symptom only shows that it did."
        aside={
          <div role="group" aria-label="Filter findings" className="inline-flex rounded-md border border-line p-0.5">
            {(["all", "cause", "symptom"] as const).map((f) => (
              <button
                key={f}
                type="button"
                aria-pressed={filter === f}
                onClick={() => setFilter(f)}
                className={`rounded px-2.5 py-1 text-xs font-medium capitalize ${filter === f ? "bg-brandSoft text-brand" : "text-subtle hover:bg-surface2"}`}
              >
                {f === "all" ? "All" : f === "cause" ? "Causes" : "Symptoms"}
              </button>
            ))}
          </div>
        }
      />
      {findings.length === 0 ? (
        <p className="px-5 py-8 text-center text-subtle">No known failure patterns and no error-level messages were found.</p>
      ) : (
        <ul className="divide-y divide-line">
          {shown.map((f) => {
            const isOpen = open === f.id;
            const isRoot = rootIds.includes(f.id);
            return (
              <li key={f.id}>
                <button
                  type="button"
                  aria-expanded={isOpen}
                  onClick={() => setOpen(isOpen ? null : f.id)}
                  className="flex w-full items-center gap-3 px-5 py-3 text-left hover:bg-surface2"
                >
                  <Icon.Chevron className={`text-subtle transition-transform ${isOpen ? "rotate-90" : ""}`} />
                  <span className="w-8 shrink-0 font-mono text-xs text-faint">{f.id}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-semibold">{f.title}</span>
                    <span className="block truncate text-xs text-subtle">
                      {baseName(f.file)}:{f.first_line}
                      {f.last_line !== f.first_line ? `-${f.last_line}` : ""}
                      {f.first_timestamp ? ` · ${f.first_timestamp}` : ""}
                      {f.other_files && f.other_files.length > 0
                        ? ` · also in ${f.other_files.length} other log${f.other_files.length === 1 ? "" : "s"}`
                        : ""}
                    </span>
                  </span>
                  <span className="hidden shrink-0 items-center gap-1.5 sm:flex">
                    {isRoot && <Badge tone="brand">Root cause</Badge>}
                    <Badge tone={SEV[f.severity]}>{f.severity}</Badge>
                    <Badge>{f.role === "cause" ? "Cause" : "Symptom"}</Badge>
                  </span>
                  <span className="w-16 shrink-0 text-right text-xs text-subtle">
                    {f.match_count} hit{f.match_count === 1 ? "" : "s"}
                  </span>
                </button>
                {isOpen && (
                  <div className="space-y-4 border-t border-line bg-surface2/50 px-5 py-4">
                    <p>{f.explanation}</p>
                    {(f.details.length > 0 || f.error_codes.length > 0 || f.attempts > 1 || f.related_files.length > 0) && (
                      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
                        {f.attempts > 1 && (
                          <>
                            <dt className="text-subtle">Attempts</dt>
                            <dd>Seen in {f.attempts} separate places{f.first_timestamp && f.last_timestamp ? `, ${f.first_timestamp} to ${f.last_timestamp}` : ""}</dd>
                          </>
                        )}
                        {f.details.length > 0 && (
                          <>
                            <dt className="text-subtle">Extracted</dt>
                            <dd className="space-y-1">
                              {f.details.map((d) => (
                                <div key={d} className="break-words font-mono text-xs">{d}</div>
                              ))}
                            </dd>
                          </>
                        )}
                        {f.error_codes.length > 0 && (
                          <>
                            <dt className="text-subtle">Error codes</dt>
                            <dd className="flex flex-wrap gap-1.5">
                              {f.error_codes.map((c) => (
                                <Badge key={c}>{c}</Badge>
                              ))}
                            </dd>
                          </>
                        )}
                        {f.related_files.length > 0 && (
                          <>
                            <dt className="text-subtle">Related logs</dt>
                            <dd className="space-y-0.5 break-words font-mono text-xs">{f.related_files.map((r) => <div key={r}>{r}</div>)}</dd>
                          </>
                        )}
                      </dl>
                    )}
                    <EvidenceViewer finding={f} />
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
