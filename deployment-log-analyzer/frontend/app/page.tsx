"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Dashboard } from "@/components/Dashboard";
import { Header } from "@/components/Header";
import { ProgressTracker, type TrackerStage } from "@/components/ProgressTracker";
import { UploadZone, type UploadOptions } from "@/components/UploadZone";
import { Card, Button, Icon } from "@/components/ui";
import { analyze, fetchConfig } from "@/lib/api";
import type { AnalysisResult, AppConfig, StreamEvent } from "@/lib/types";

type Phase = "idle" | "running" | "done" | "error";

const FALLBACK_STAGES = [
  { id: "extract", label: "Extract" },
  { id: "detect", label: "Detect" },
  { id: "scan", label: "Scan" },
  { id: "evidence", label: "Evidence" },
  { id: "analyze", label: "Analyse" },
  { id: "report", label: "Report" },
];
// Short labels so seven steps fit on one row.
const SHORT: Record<string, string> = {
  extract: "Extract", detect: "Detect type", scan: "Find errors", evidence: "Evidence", analyze: "Root cause", report: "Report",
};

function freshStages(config: AppConfig | null): TrackerStage[] {
  const backend = (config?.stages ?? FALLBACK_STAGES).map((s) => ({ id: s.id, label: SHORT[s.id] ?? s.label, status: "pending" as const }));
  return [{ id: "upload", label: "Upload", status: "pending" }, ...backend];
}

export default function Home() {
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [backend, setBackend] = useState<"checking" | "online" | "offline">("checking");
  const [phase, setPhase] = useState<Phase>("idle");
  const [stages, setStages] = useState<TrackerStage[]>(freshStages(null));
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    const ctl = new AbortController();
    fetchConfig(ctl.signal)
      .then((c) => (setConfig(c), setBackend("online")))
      .catch((e) => e.name !== "AbortError" && setBackend("offline"));
    return () => ctl.abort();
  }, []);

  const patch = useCallback((id: string, change: Partial<TrackerStage>) => setStages((prev) => prev.map((s) => (s.id === id ? { ...s, ...change } : s))), []);

  const reset = useCallback(() => {
    abort.current?.abort();
    setPhase("idle");
    setResult(null);
    setError(null);
    setStages(freshStages(config));
  }, [config]);

  const start = useCallback(
    async (files: File[], opts: UploadOptions) => {
      const ctl = new AbortController();
      abort.current = ctl;
      setError(null);
      setResult(null);
      setStages(freshStages(config).map((s) => (s.id === "upload" ? { ...s, status: "running" as const, percent: 0 } : s)));
      setPhase("running");

      const onEvent = (ev: StreamEvent) => {
        if (ev.type === "progress") {
          patch("upload", { status: "done", percent: 100 });
          patch(ev.stage, { status: ev.status, message: ev.message, percent: ev.percent });
        } else if (ev.type === "result") {
          setResult(ev.data);
          setPhase("done");
        } else if (ev.type === "error") {
          setError(ev.message);
          setPhase("error");
          setStages((prev) => prev.map((s) => (s.status === "running" ? { ...s, status: "error" } : s)));
        }
      };

      try {
        await analyze({
          files,
          ...opts,
          signal: ctl.signal,
          onUpload: (p) => patch("upload", { status: p >= 100 ? "done" : "running", percent: p, message: `${p}%` }),
          onEvent,
        });
      } catch (e) {
        if ((e as Error).name === "AbortError") return;
        setError((e as Error).message);
        setPhase("error");
        setStages((prev) => prev.map((s) => (s.status === "running" ? { ...s, status: "error" } : s)));
      }
    },
    [config, patch],
  );

  return (
    <>
      <Header onHome={reset} backend={backend} />
      <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">
        {backend === "offline" && phase === "idle" && (
          <div role="alert" className="mb-5 flex gap-2.5 rounded-lg bg-dangerSoft px-4 py-3 text-sm">
            <Icon.Alert className="mt-0.5 text-danger" />
            <span>The analysis service is not reachable. Start the backend (see the README) and refresh this page.</span>
          </div>
        )}

        {phase === "idle" && <UploadZone config={config} onAnalyze={start} disabled={backend === "offline"} />}

        {(phase === "running" || phase === "error") && (
          <div className="space-y-4">
            <ProgressTracker stages={stages} onCancel={phase === "running" ? reset : undefined} />
            {phase === "error" && (
              <Card>
                <div className="flex flex-col gap-3 p-5 sm:flex-row sm:items-center sm:justify-between" role="alert">
                  <div className="flex gap-2.5">
                    <Icon.Alert className="mt-0.5 text-danger" />
                    <div>
                      <div className="font-semibold">The analysis could not be completed</div>
                      <p className="text-subtle">{error}</p>
                    </div>
                  </div>
                  <Button variant="primary" onClick={reset}>Try again</Button>
                </div>
              </Card>
            )}
          </div>
        )}

        {phase === "done" && result && <Dashboard result={result} onReset={reset} />}
      </main>
      <footer className="mx-auto max-w-6xl px-4 pb-8 text-xs text-faint sm:px-6">
        Nothing you upload is stored. Analysis runs in memory and is discarded when it finishes.
      </footer>
    </>
  );
}
