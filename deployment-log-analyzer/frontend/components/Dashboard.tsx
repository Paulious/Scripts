"use client";

import type { AnalysisResult, AppConfig } from "@/lib/types";
import { download, seconds } from "@/lib/format";
import { AiPanel, type AiStatus } from "./AiPanel";
import { ConfidenceRing, tone } from "./ConfidenceRing";
import { FilesTable } from "./FilesTable";
import { FindingsTable } from "./FindingsTable";
import { Badge, Button, Card, CardHeader, CopyButton, Icon, Stat } from "./ui";

function List({ title, items, empty }: { title: string; items: string[]; empty?: string }) {
  if (!items.length && !empty) return null;
  return (
    <Card>
      <CardHeader title={title} />
      {items.length ? (
        <ul className="space-y-2 px-5 py-4">
          {items.map((t, i) => (
            <li key={i} className="flex gap-2.5">
              <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-lineStrong" aria-hidden="true" />
              <span className="min-w-0 break-words">{t}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="px-5 py-4 text-subtle">{empty}</p>
      )}
    </Card>
  );
}

export type View = "pattern" | "ai";

interface DashboardProps {
  pattern: AnalysisResult;
  ai: AnalysisResult | null;
  view: View;
  onView: (v: View) => void;
  config: AppConfig | null;
  aiStatus: AiStatus;
  aiMessage?: string;
  aiError?: string | null;
  onRunAi: (provider: string, redact: boolean) => void;
  onReset: () => void;
}

export function Dashboard({ pattern, ai, view, onView, config, aiStatus, aiMessage, aiError, onRunAi, onReset }: DashboardProps) {
  // Findings, evidence and files are identical in both views; only the written analysis differs.
  const result = view === "ai" && ai ? ai : pattern;
  const { analysis: a, stats } = result;
  const rc = a.root_cause;
  const causeCount = result.findings.filter((f) => f.role === "cause").length;
  const stamp = result.generated_at.replace(/[^0-9]/g, "").slice(0, 12);

  return (
    <div className="min-w-0 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold leading-7">Analysis results</h1>
          <p className="text-xs text-subtle">
            {result.generated_at} · {a.provider === "none" ? "Pattern library" : `${a.provider}${a.model ? ` / ${a.model}` : ""}`}
            {result.context ? ` · ${result.context}` : ""}
          </p>
        </div>
        {ai && (
          <div role="group" aria-label="Which analysis to show" className="inline-flex rounded-md border border-line bg-surface p-0.5">
            {(["pattern", "ai"] as const).map((v) => (
              <button
                key={v}
                type="button"
                aria-pressed={view === v}
                onClick={() => onView(v)}
                className={`rounded px-3 py-1 text-sm font-semibold ${view === v ? "bg-brandSoft text-brand" : "text-subtle hover:bg-surface2"}`}
              >
                {v === "pattern" ? "Pattern analysis" : "AI analysis"}
              </button>
            ))}
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <CopyButton text={result.report_markdown} label="Copy Markdown" className="h-8 px-3 text-sm font-semibold" />
          <Button variant="primary" onClick={() => download(`deployment-analysis-${stamp}.md`, result.report_markdown)}>
            <Icon.Download /> Export report
          </Button>
          <Button onClick={onReset}>New analysis</Button>
        </div>
      </div>

      {!ai && <AiPanel config={config} status={aiStatus} message={aiMessage} error={aiError} onRun={onRunAi} />}

      {(a.degraded || a.notes.length > 0) && (
        <div role="status" className="flex gap-2.5 rounded-lg border border-transparent bg-warnSoft px-4 py-3 text-warn">
          <Icon.Alert className="mt-0.5" />
          <div className="text-sm text-fg">{a.notes.join(" ") || "Some steps used fallback behaviour."}</div>
        </div>
      )}

      <Card>
        <div className="grid grid-cols-2 divide-x divide-y divide-line sm:grid-cols-3 lg:grid-cols-6 lg:divide-y-0">
          <Stat label="Confidence" value={rc ? `${rc.confidence.score}%` : "n/a"} sub={rc ? rc.confidence.label : "no root cause"} tone={rc ? (tone(rc.confidence.label) === "ok" ? "ok" : tone(rc.confidence.label) === "danger" ? "danger" : undefined) : undefined} />
          <Stat label="Files analysed" value={stats.files_analyzed} sub={stats.files_skipped ? `${stats.files_skipped} skipped` : "none skipped"} />
          <Stat label="Lines scanned" value={stats.total_lines.toLocaleString()} />
          <Stat label="Findings" value={stats.findings} sub={`${causeCount} cause${causeCount === 1 ? "" : "s"}`} tone={stats.findings ? "danger" : "ok"} />
          <Stat label="Error lines" value={stats.errors.toLocaleString()} sub="after noise filter" />
          <Stat label="Time taken" value={seconds(stats.duration_ms)} />
        </div>
      </Card>

      <Card>
        <div className="p-5 sm:p-6">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-subtle">Summary</h2>
          <p className="mt-2 max-w-4xl break-words text-[15px] leading-6">{a.summary}</p>
        </div>
      </Card>

      {rc ? (
        <Card>
          <div className="flex flex-col gap-5 p-5 sm:flex-row sm:p-6">
            <ConfidenceRing score={rc.confidence.score} label={rc.confidence.label} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-xs font-semibold uppercase tracking-wide text-subtle">{rc.tied_to_failure === false ? "Most notable problem" : "Most likely root cause"}</h2>
                <Badge tone="brand">{rc.category}</Badge>
                {rc.finding_ids.map((id) => (
                  <Badge key={id}>{id}</Badge>
                ))}
              </div>
              <h3 className="mt-1.5 text-lg font-semibold leading-6">{rc.title}</h3>
              <p className="mt-2 break-words leading-6">{rc.explanation}</p>
              {rc.reasoning && (
                <div className="mt-4 rounded-md border border-line bg-surface2 px-4 py-3">
                  <div className="text-xs font-semibold text-subtle">Why we think so</div>
                  <p className="mt-1 break-words leading-6">{rc.reasoning}</p>
                </div>
              )}
              <details className="mt-4 group">
                <summary className="cursor-pointer select-none text-sm font-semibold text-brand">How the confidence score was worked out</summary>
                <ul className="mt-3 space-y-3">
                  {rc.confidence.factors.map((f) => (
                    <li key={f.name}>
                      <div className="flex justify-between text-sm">
                        <span className="font-medium">{f.name}</span>
                        <span className="text-subtle tabular-nums">
                          {Math.round(f.score * 100)}% · weight {Math.round(f.weight * 100)}%
                        </span>
                      </div>
                      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface2">
                        <div className="h-full rounded-full bg-brand" style={{ width: `${Math.round(f.score * 100)}%` }} />
                      </div>
                      <p className="mt-1 text-xs text-subtle">{f.detail}</p>
                    </li>
                  ))}
                </ul>
                {rc.confidence.llm_reported !== null && (
                  <p className="mt-3 text-xs text-subtle">
                    The model reported {rc.confidence.llm_reported}%. The final figure blends it with the evidence score and can never be more than 10 points above it.
                  </p>
                )}
              </details>
            </div>
          </div>
        </Card>
      ) : (
        <Card>
          <div className="flex gap-3 p-5 sm:p-6">
            <Icon.Info className="mt-0.5 text-brand" />
            <p>No failure was identified in these logs. If something did fail, upload the installer log and the Intune Management Extension logs from the same time.</p>
          </div>
        </Card>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="min-w-0 space-y-5 lg:col-span-2">
          {a.remediation.length > 0 && (
            <Card>
              <CardHeader title="What to do" sub="In the order you would do it." />
              <ol className="divide-y divide-line">
                {a.remediation.map((s) => (
                  <li key={s.order} className="flex gap-4 px-5 py-4">
                    <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-brandSoft text-xs font-semibold text-brand">{s.order}</span>
                    <div className="min-w-0 flex-1">
                      <div className="font-semibold">{s.action}</div>
                      {s.detail && <p className="mt-0.5 text-subtle">{s.detail}</p>}
                      {s.command && (
                        <div className="mt-2 flex items-start gap-2 rounded-md border border-line bg-code py-1.5 pl-3 pr-1.5">
                          <code className="min-w-0 flex-1 overflow-x-auto whitespace-pre py-0.5 font-mono text-xs leading-5">{s.command}</code>
                          <CopyButton text={s.command} />
                        </div>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            </Card>
          )}
          {a.contributing_factors.length > 0 && <List title="Other things worth knowing" items={a.contributing_factors} />}
        </div>
        <div className="min-w-0 space-y-5">
          <List title="How to confirm it is fixed" items={a.verification} />
          <List title="Checked and ruled out" items={a.ruled_out} />
          <List title="Data that would help" items={a.further_data} />
        </div>
      </div>

      <FindingsTable findings={result.findings} rootIds={rc?.finding_ids ?? []} />
      <FilesTable files={result.files} groups={result.skipped_groups} />

      {result.suppressed.length > 0 && (
        <Card>
          <CardHeader title="Routine noise filtered out" sub="Lines that look like errors but are normal. They were not counted as findings." />
          <ul className="divide-y divide-line">
            {result.suppressed.map((s) => (
              <li key={s.id} className="flex items-start justify-between gap-4 px-5 py-3">
                <p className="min-w-0 text-sm">{s.reason}</p>
                <span className="shrink-0 text-xs text-subtle tabular-nums">{s.count.toLocaleString()} line{s.count === 1 ? "" : "s"}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
