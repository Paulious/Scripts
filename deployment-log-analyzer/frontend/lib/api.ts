import type { AnalysisResult, AppConfig, StreamEvent } from "./types";

// Empty string means "same origin" (used when a proxy serves the site and /api together).
export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");

export async function fetchConfig(signal?: AbortSignal): Promise<AppConfig> {
  const res = await fetch(`${API_URL}/api/config`, { signal, cache: "no-store" });
  if (!res.ok) throw new Error(`The analysis service answered ${res.status}`);
  return res.json();
}

type ReadyEvent = { type: "result_ready"; id: string; parts: number };

/** The result is too big for one reply on some hosts, so it is collected in small pieces. */
async function collectResult(ev: ReadyEvent, signal: AbortSignal): Promise<AnalysisResult> {
  const pieces: string[] = [];
  for (let i = 0; i < ev.parts; i++) {
    let text: string | null = null;
    for (let attempt = 0; attempt < 3 && text === null; attempt++) {
      try {
        const res = await fetch(`${API_URL}/api/result/${ev.id}/${i}`, { signal, cache: "no-store" });
        if (res.status === 404) throw new Error("The result expired before it could be collected. Run the analysis again.");
        if (res.ok) text = await res.text();
      } catch (err) {
        if (signal.aborted || (err instanceof Error && err.message.startsWith("The result expired"))) throw err;
      }
    }
    if (text === null) throw new Error("Could not collect the finished result from the analysis service.");
    pieces.push(text);
  }
  // Tell the server it can forget it. Best effort.
  fetch(`${API_URL}/api/result/${ev.id}`, { method: "DELETE" }).catch(() => undefined);
  return JSON.parse(pieces.join("")) as AnalysisResult;
}

interface StreamOptions {
  path: string;
  body: FormData | string;
  json?: boolean;
  onUpload?: (percent: number) => void;
  onEvent: (event: StreamEvent) => void;
  signal: AbortSignal;
}

/**
 * POST and read a newline-delimited JSON progress stream.
 * XMLHttpRequest is used on purpose: unlike fetch it reports upload progress,
 * and it exposes the response text as it arrives.
 */
function postStream(opts: StreamOptions): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_URL}${opts.path}`);
    if (opts.json) xhr.setRequestHeader("Content-Type", "application/json");
    let consumed = 0;
    let buffer = "";
    let finished = false;
    const pending: Promise<void>[] = [];
    let failed: Error | null = null;

    const drain = () => {
      buffer += xhr.responseText.slice(consumed);
      consumed = xhr.responseText.length;
      let nl: number;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        try {
          const ev = JSON.parse(line) as StreamEvent | ReadyEvent;
          if (ev.type === "result_ready") {
            finished = true;
            pending.push(
              collectResult(ev, opts.signal).then(
                (data) => opts.onEvent({ type: "result", data }),
                (err) => {
                  failed = err instanceof Error ? err : new Error(String(err));
                },
              ),
            );
          } else {
            if (ev.type === "result" || ev.type === "error") finished = true;
            opts.onEvent(ev);
          }
        } catch {
          /* ignore a malformed line rather than lose the whole run */
        }
      }
    };

    if (opts.onUpload) {
      const up = opts.onUpload;
      xhr.upload.onprogress = (e) => e.lengthComputable && up(Math.round((100 * e.loaded) / e.total));
      xhr.upload.onload = () => up(100);
    }
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
      if (!finished) {
        reject(new Error("The connection closed before the analysis finished"));
        return;
      }
      Promise.all(pending).then(() => (failed ? reject(failed) : resolve()));
    };
    xhr.onerror = () => {
      // Say how far it got: that tells us whether the request never arrived or the stream was cut part way.
      const got = xhr.responseText.length;
      const where =
        xhr.readyState <= 1
          ? "The request never got a reply (nothing came back)."
          : got > 0
            ? `The connection dropped part way through the reply (${Math.round(got / 1024)} KB received).`
            : "The connection dropped before any progress was received.";
      reject(new Error(`Could not reach the analysis service. ${where} Check the backend is running and look at its logs.`));
    };
    xhr.onabort = () => reject(new DOMException("Cancelled", "AbortError"));
    opts.signal.addEventListener("abort", () => xhr.abort());
    xhr.send(opts.body);
  });
}

export interface AnalyzeOptions {
  files: File[];
  context: string;
  onUpload: (percent: number) => void;
  onEvent: (event: StreamEvent) => void;
  signal: AbortSignal;
}

/** Step 1: upload and run the pattern pass. No AI provider is involved. */
export function analyze(opts: AnalyzeOptions): Promise<void> {
  const form = new FormData();
  for (const f of opts.files) form.append("files", f, f.name);
  form.append("provider", "none");
  form.append("context", opts.context);
  return postStream({ path: "/api/analyze", body: form, onUpload: opts.onUpload, onEvent: opts.onEvent, signal: opts.signal });
}

export interface EnhanceOptions {
  result: AnalysisResult;
  provider: string;
  redact: boolean;
  onEvent: (event: StreamEvent) => void;
  signal: AbortSignal;
}

/** Step 2 (optional): send the pattern result back and get an AI-written analysis. */
export function enhance(opts: EnhanceOptions): Promise<void> {
  return postStream({
    path: "/api/enhance",
    json: true,
    body: JSON.stringify({ result: opts.result, provider: opts.provider, redact: opts.redact }),
    onEvent: opts.onEvent,
    signal: opts.signal,
  });
}
