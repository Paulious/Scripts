"use client";

import { useCallback, useId, useRef, useState } from "react";
import type { AppConfig } from "@/lib/types";
import { bytes } from "@/lib/format";
import { Button, Card, Icon } from "./ui";

export interface UploadOptions {
  provider: string;
  context: string;
  redact: boolean;
}

interface Props {
  config: AppConfig | null;
  onAnalyze: (files: File[], opts: UploadOptions) => void;
  disabled?: boolean;
}

export function UploadZone({ config, onAnalyze, disabled }: Props) {
  const [files, setFiles] = useState<File[]>([]);
  const [over, setOver] = useState(false);
  const [context, setContext] = useState("");
  const [provider, setProvider] = useState<string>("");
  const [redact, setRedact] = useState(true);
  const input = useRef<HTMLInputElement>(null);
  const ids = { ctx: useId(), prov: useId(), red: useId() };

  const chosen = provider || config?.default_provider || "none";
  const providerInfo = config?.providers.find((p) => p.id === chosen);
  const usesLlm = chosen !== "none";
  const maxMb = config?.limits.max_upload_mb ?? 200;
  const total = files.reduce((n, f) => n + f.size, 0);
  const tooBig = total > maxMb * 1024 * 1024;

  const add = useCallback((list: FileList | File[]) => {
    setFiles((prev) => {
      const seen = new Set(prev.map((f) => `${f.name}:${f.size}:${f.lastModified}`));
      const next = [...prev];
      for (const f of Array.from(list)) {
        const key = `${f.name}:${f.size}:${f.lastModified}`;
        if (!seen.has(key)) {
          seen.add(key);
          next.push(f);
        }
      }
      return next;
    });
  }, []);

  return (
    <Card>
      <div className="p-5 sm:p-6">
        <h1 className="text-xl font-semibold leading-7">Analyse deployment logs</h1>
        <p className="mt-1 max-w-2xl text-subtle">
          Drop a ZIP of logs (Intune Management Extension, Patch My PC, MSI, PSADT, vendor installers) or individual log files. You get the most likely
          root cause, the lines that prove it, and the steps to fix it.
        </p>

        <div
          role="button"
          tabIndex={0}
          aria-label="Choose log files or drop them here"
          onClick={() => input.current?.click()}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), input.current?.click())}
          onDragOver={(e) => (e.preventDefault(), setOver(true))}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setOver(false);
            if (e.dataTransfer.files.length) add(e.dataTransfer.files);
          }}
          className={`mt-5 flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors ${
            over ? "border-brand bg-brandSoft" : "border-lineStrong bg-surface2 hover:border-brand hover:bg-brandSoft"
          }`}
        >
          <span className="grid h-11 w-11 place-items-center rounded-full bg-surface text-brand shadow-sm">
            <Icon.Upload className="h-5 w-5" />
          </span>
          <p className="mt-3 text-sm font-semibold">Drag and drop files here, or click to browse</p>
          <p className="mt-1 text-xs text-subtle">.zip, .tar.gz, .gz, .log, .txt and .csv. Up to {maxMb} MB. Nested archives are opened automatically.</p>
          <input
            ref={input}
            type="file"
            multiple
            className="sr-only"
            tabIndex={-1}
            onChange={(e) => {
              if (e.target.files) add(e.target.files);
              e.target.value = "";
            }}
          />
        </div>

        {files.length > 0 && (
          <ul className="mt-4 divide-y divide-line rounded-md border border-line" aria-label="Selected files">
            {files.map((f, i) => (
              <li key={`${f.name}-${i}`} className="flex items-center gap-3 px-3 py-2">
                {/\.(zip|gz|tgz|tar|bz2|xz)$/i.test(f.name) ? <Icon.Archive className="text-subtle" /> : <Icon.File className="text-subtle" />}
                <span className="min-w-0 flex-1 truncate font-medium">{f.name}</span>
                <span className="text-xs text-subtle">{bytes(f.size)}</span>
                <button
                  type="button"
                  aria-label={`Remove ${f.name}`}
                  onClick={() => setFiles((prev) => prev.filter((_, j) => j !== i))}
                  className="grid h-6 w-6 place-items-center rounded text-subtle hover:bg-surface2 hover:text-fg"
                >
                  <Icon.Close />
                </button>
              </li>
            ))}
          </ul>
        )}
        {tooBig && (
          <p className="mt-2 flex items-center gap-1.5 text-sm text-danger" role="alert">
            <Icon.Alert /> {bytes(total)} is over the {maxMb} MB limit. Remove some files or zip only the relevant logs.
          </p>
        )}

        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div className="md:col-span-2">
            <label htmlFor={ids.ctx} className="mb-1 block text-sm font-semibold">
              What were you deploying? <span className="font-normal text-faint">(optional)</span>
            </label>
            <textarea
              id={ids.ctx}
              rows={2}
              maxLength={2000}
              value={context}
              onChange={(e) => setContext(e.target.value)}
              placeholder="For example: Dell Command Update 5.7.2 as a Win32 app via Patch My PC, System context, fails on new Autopilot devices"
              className="w-full resize-y rounded-md border border-lineStrong bg-surface px-3 py-2 text-sm placeholder:text-faint"
            />
          </div>
          <div>
            <label htmlFor={ids.prov} className="mb-1 block text-sm font-semibold">
              Analysis engine
            </label>
            <select
              id={ids.prov}
              value={chosen}
              onChange={(e) => setProvider(e.target.value)}
              className="h-9 w-full rounded-md border border-lineStrong bg-surface px-2 text-sm"
            >
              {(config?.providers ?? [{ id: "none", label: "Pattern library only (no LLM)", model: null, configured: true }]).map((p) => (
                <option key={p.id} value={p.id} disabled={!p.configured}>
                  {p.label}
                  {p.model && p.configured ? ` (${p.model})` : ""}
                  {!p.configured ? " - not configured on the server" : ""}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <label htmlFor={ids.red} className={`flex items-center gap-2 text-sm ${usesLlm ? "" : "opacity-50"}`}>
              <input id={ids.red} type="checkbox" checked={redact} disabled={!usesLlm} onChange={(e) => setRedact(e.target.checked)} className="h-4 w-4 accent-[var(--brand)]" />
              Remove passwords, tokens, emails and user names before sending
            </label>
          </div>
        </div>

        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
          <p className="flex max-w-xl items-start gap-2 text-xs text-subtle">
            <Icon.Info className="mt-0.5" />
            <span>
              Files are processed in memory and discarded when the analysis ends. Nothing is stored.
              {usesLlm && providerInfo ? ` Relevant log excerpts are sent to ${providerInfo.label} to write the analysis.` : " No data leaves the server in this mode."}
            </span>
          </p>
          <Button
            variant="primary"
            className="h-9 px-5"
            disabled={disabled || files.length === 0 || tooBig}
            onClick={() => onAnalyze(files, { provider: chosen, context, redact })}
          >
            Analyse logs
          </Button>
        </div>
      </div>
    </Card>
  );
}
