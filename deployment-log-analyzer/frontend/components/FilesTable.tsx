"use client";

import { useState } from "react";
import type { LogFileInfo, SkippedGroup } from "@/lib/types";
import { bytes } from "@/lib/format";
import { Badge, Card, CardHeader, Icon } from "./ui";

export function FilesTable({ files, groups }: { files: LogFileInfo[]; groups: SkippedGroup[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Card>
      <CardHeader title="Files analysed" sub="Each file is matched to a parser by its content, not its name." />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[40rem] text-left text-sm">
          <thead className="text-xs text-subtle">
            <tr className="border-b border-line">
              <th className="px-5 py-2 font-medium">File</th>
              <th className="px-3 py-2 font-medium">Detected as</th>
              <th className="px-3 py-2 text-right font-medium">Lines</th>
              <th className="px-3 py-2 text-right font-medium">Errors</th>
              <th className="px-5 py-2 text-right font-medium">Size</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {files.map((f) => {
              const facts = Object.entries(f.facts);
              const isOpen = open === f.path;
              return (
                <FileRow key={f.path} f={f} facts={facts} isOpen={isOpen} toggle={() => setOpen(isOpen ? null : f.path)} />
              );
            })}
          </tbody>
        </table>
      </div>
      {groups.length > 0 && (
        <div className="border-t border-line px-5 py-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-subtle">Not read</h3>
          <ul className="mt-2 space-y-1.5 text-sm">
            {groups.map((g) => (
              <li key={g.reason} className="flex gap-3">
                <span className="w-10 shrink-0 text-right font-semibold tabular-nums">{g.count}</span>
                <span className="min-w-0">
                  {g.reason}
                  {g.examples.length > 0 && <span className="text-faint"> ({g.examples.join(", ")}{g.count > g.examples.length ? ", ..." : ""})</span>}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

function FileRow({ f, facts, isOpen, toggle }: { f: LogFileInfo; facts: [string, string][]; isOpen: boolean; toggle: () => void }) {
  return (
    <>
      <tr className={facts.length ? "cursor-pointer hover:bg-surface2" : ""} onClick={facts.length ? toggle : undefined}>
        <td className="max-w-[22rem] px-5 py-2.5">
          <div className="flex items-center gap-2">
            {facts.length ? <Icon.Chevron className={`text-subtle transition-transform ${isOpen ? "rotate-90" : ""}`} /> : <span className="w-4" />}
            <span className="min-w-0">
              <span className="block truncate font-medium" title={f.path}>{f.path.split("/").pop()}</span>
              {f.path.includes("/") && (
                <span className="block truncate text-xs text-faint">{f.path.split("/").slice(0, -1).join("/").replace(/^\(\d+\)\s+(?:FoldersFiles|Command|RegistryKey|Events)\s+/, "")}</span>
              )}
            </span>
          </div>
        </td>
        <td className="px-3 py-2.5">
          <Badge tone={f.log_type === "generic" ? "neutral" : "brand"} title={`Detection confidence ${Math.round(f.detection_confidence * 100)}%`}>
            {f.log_type_label}
          </Badge>
        </td>
        <td className="px-3 py-2.5 text-right tabular-nums">{f.line_count.toLocaleString()}</td>
        <td className={`px-3 py-2.5 text-right tabular-nums ${f.error_count ? "font-semibold text-danger" : "text-subtle"}`}>{f.error_count}</td>
        <td className="px-5 py-2.5 text-right text-subtle tabular-nums">{bytes(f.size_bytes)}</td>
      </tr>
      {isOpen && facts.length > 0 && (
        <tr className="bg-surface2/50">
          <td colSpan={5} className="px-5 py-3">
            <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-[auto_1fr]">
              <dt className="text-subtle">Encoding</dt>
              <dd>{f.encoding}</dd>
              {f.first_timestamp && (
                <>
                  <dt className="text-subtle">Time span</dt>
                  <dd>{f.first_timestamp} to {f.last_timestamp}</dd>
                </>
              )}
              {facts.map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-subtle">{k}</dt>
                  <dd className="break-words">{v}</dd>
                </div>
              ))}
            </dl>
          </td>
        </tr>
      )}
    </>
  );
}
