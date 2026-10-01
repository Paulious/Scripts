import type { StageStatus } from "@/lib/types";
import { Card, Icon } from "./ui";

export interface TrackerStage {
  id: string;
  label: string;
  status: StageStatus;
  message?: string;
  percent?: number;
}

function Dot({ status, index }: { status: StageStatus; index: number }) {
  if (status === "done")
    return (
      <span className="grid h-7 w-7 place-items-center rounded-full bg-ok text-white">
        <Icon.Check />
      </span>
    );
  if (status === "running")
    return (
      <span className="grid h-7 w-7 place-items-center rounded-full bg-brand text-onBrand">
        <Icon.Spinner />
      </span>
    );
  if (status === "error")
    return (
      <span className="grid h-7 w-7 place-items-center rounded-full bg-danger text-white">
        <Icon.Close />
      </span>
    );
  return <span className="grid h-7 w-7 place-items-center rounded-full border border-lineStrong bg-surface text-xs font-semibold text-faint">{index + 1}</span>;
}

export function ProgressTracker({ stages, onCancel }: { stages: TrackerStage[]; onCancel?: () => void }) {
  const active = stages.find((s) => s.status === "running") ?? stages.find((s) => s.status === "error");
  const doneCount = stages.filter((s) => s.status === "done").length;
  const overall = Math.round((100 * (doneCount + (active?.percent ?? 0) / 100)) / stages.length);

  return (
    <Card>
      <div className="p-5 sm:p-6">
        <div className="flex items-center justify-between gap-3">
          <h1 className="text-xl font-semibold leading-7">Analysing your logs</h1>
          {onCancel && (
            <button type="button" onClick={onCancel} className="text-sm font-semibold text-brand hover:underline">
              Cancel
            </button>
          )}
        </div>

        <ol className="mt-6 grid gap-4 sm:grid-cols-7" aria-label="Progress">
          {stages.map((s, i) => (
            <li key={s.id} className="flex items-center gap-3 sm:flex-col sm:items-start sm:gap-2" aria-current={s.status === "running" ? "step" : undefined}>
              <div className="flex items-center sm:w-full">
                <Dot status={s.status} index={i} />
                {i < stages.length - 1 && (
                  <span className={`ml-2 hidden h-0.5 flex-1 rounded sm:block ${s.status === "done" ? "bg-ok" : "bg-line"}`} aria-hidden="true" />
                )}
              </div>
              <span className={`text-sm leading-4 ${s.status === "pending" ? "text-faint" : "font-semibold"}`}>{s.label}</span>
            </li>
          ))}
        </ol>

        <div className="mt-6" role="status" aria-live="polite">
          <div className="mb-1.5 flex justify-between text-xs text-subtle">
            <span>{active ? `${active.label}${active.message ? `: ${active.message}` : ""}` : "Starting"}</span>
            <span>{overall}%</span>
          </div>
          <div className="relative h-1.5 overflow-hidden rounded-full bg-surface2" role="progressbar" aria-valuenow={overall} aria-valuemin={0} aria-valuemax={100}>
            <div className="h-full rounded-full bg-brand transition-all duration-300" style={{ width: `${Math.max(overall, 4)}%` }} />
          </div>
          {active?.id === "analyze" && (
            <p className="mt-3 text-xs text-subtle">The analysis engine is reading the evidence. This usually takes between 10 seconds and 2 minutes.</p>
          )}
        </div>
      </div>
    </Card>
  );
}
