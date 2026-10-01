import type { AppConfig, StreamEvent } from "./types";

export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");

export async function fetchConfig(signal?: AbortSignal): Promise<AppConfig> {
  const res = await fetch(`${API_URL}/api/config`, { signal, cache: "no-store" });
  if (!res.ok) throw new Error(`The analysis service answered ${res.status}`);
  return res.json();
}

export interface AnalyzeOptions {
  files: File[];
  provider: string;
  context: string;
  redact: boolean;
  onUpload: (percent: number) => void;
  onEvent: (event: StreamEvent) => void;
  signal: AbortSignal;
}

/**
 * Upload the files and read the NDJSON progress stream.
 * XMLHttpRequest is used on purpose: unlike fetch it reports upload progress,
 * and it exposes the response text as it arrives.
 */
export function analyze(opts: AnalyzeOptions): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_URL}/api/analyze`);
    let consumed = 0;
    let buffer = "";
    let finished = false;

    const drain = () => {
      buffer += xhr.responseText.slice(consumed);
      consumed = xhr.responseText.length;
      let nl: number;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        try {
          const ev = JSON.parse(line) as StreamEvent;
          if (ev.type === "result" || ev.type === "error") finished = true;
          opts.onEvent(ev);
        } catch {
          /* a partial line can't happen here because we split on newlines */
        }
      }
    };

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) opts.onUpload(Math.round((100 * e.loaded) / e.total));
    };
    xhr.upload.onload = () => opts.onUpload(100);
    xhr.onprogress = drain;
    xhr.onload = () => {
      if (xhr.status >= 400) {
        let msg = `The analysis service answered ${xhr.status}`;
        try {
          const body = JSON.parse(xhr.responseText);
          if (typeof body.detail === "string") msg = body.detail;
        } catch {
          /* keep default */
        }
        reject(new Error(msg));
        return;
      }
      drain();
      if (!finished) reject(new Error("The connection closed before the analysis finished"));
      else resolve();
    };
    xhr.onerror = () => reject(new Error("Could not reach the analysis service. Check that the backend is running."));
    xhr.onabort = () => reject(new DOMException("Cancelled", "AbortError"));
    opts.signal.addEventListener("abort", () => xhr.abort());

    const form = new FormData();
    for (const f of opts.files) form.append("files", f, f.name);
    form.append("provider", opts.provider);
    form.append("context", opts.context);
    form.append("redact", String(opts.redact));
    xhr.send(form);
  });
}
