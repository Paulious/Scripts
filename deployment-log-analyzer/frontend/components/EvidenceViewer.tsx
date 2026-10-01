"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Finding } from "@/lib/types";
import { CopyButton } from "./ui";

export function EvidenceViewer({ finding }: { finding: Finding }) {
  const [idx, setIdx] = useState(0);
  const [hideNoise, setHideNoise] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const win = finding.evidence[idx];

  const lines = useMemo(() => (win ? win.lines.filter((l) => !(hideNoise && l.noise && !l.match)) : []), [win, hideNoise]);
  const hidden = win ? win.lines.length - lines.length : 0;

  // Centre the matched line when the window opens or changes.
  useEffect(() => {
    const el = box.current?.querySelector<HTMLElement>("[data-anchor='true']");
    if (el && box.current) box.current.scrollTop = Math.max(0, el.offsetTop - box.current.clientHeight / 2 + el.clientHeight / 2);
  }, [idx, hideNoise, finding.id]);

  if (!win) {
    return <p className="text-sm text-subtle">Evidence for this finding was trimmed to keep the response small. First match: <code className="font-mono text-xs">{finding.sample}</code></p>;
  }

  const plain = win.lines.map((l) => `${l.n}: ${l.text}`).join("\n");
  const label = (i: number) => (finding.evidence.length > 1 ? (i === 0 ? "First attempt" : "Latest attempt") : "Evidence");

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs text-subtle">
          {finding.evidence.length > 1 ? (
            <div role="tablist" className="inline-flex rounded-md border border-line p-0.5">
              {finding.evidence.map((_, i) => (
                <button
                  key={i}
                  role="tab"
                  aria-selected={i === idx}
                  onClick={() => setIdx(i)}
                  className={`rounded px-2 py-0.5 text-xs font-medium ${i === idx ? "bg-brandSoft text-brand" : "hover:bg-surface2"}`}
                >
                  {label(i)}
                </button>
              ))}
            </div>
          ) : null}
          <span className="min-w-0 break-words">
            <span className="font-mono">{win.file.split("/").pop()}</span> lines {win.start_line}-{win.end_line} ({win.lines.length} lines, match at {win.anchor_line})
          </span>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-subtle">
            <input type="checkbox" checked={hideNoise} onChange={(e) => setHideNoise(e.target.checked)} className="accent-[var(--brand)]" />
            Hide routine lines{hideNoise && hidden ? ` (${hidden})` : ""}
          </label>
          <CopyButton text={plain} label="Copy lines" />
        </div>
      </div>

      <div ref={box} className="relative max-h-[28rem] overflow-auto rounded-md border border-line bg-code" tabIndex={0} aria-label="Log excerpt">
        <table className="w-full border-collapse font-mono text-xs leading-5">
          <tbody>
            {lines.map((l) => (
              <tr
                key={l.n}
                data-anchor={!!l.anchor}
                className={
                  l.anchor
                    ? "bg-dangerSoft shadow-[inset_3px_0_0_var(--danger)]"
                    : l.match
                      ? "bg-warnSoft shadow-[inset_3px_0_0_var(--warn)]"
                      : l.noise
                        ? "text-faint"
                        : ""
                }
              >
                <td className="sticky left-0 w-14 select-none border-r border-line bg-inherit px-2 text-right align-top text-faint">{l.n}</td>
                <td className="whitespace-pre px-3 align-top">{l.text || " "}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
