"use client";

import { useId, useState } from "react";
import type { AppConfig } from "@/lib/types";
import { Button, Card, Icon } from "./ui";

export type AiStatus = "idle" | "running" | "error";

interface Props {
  config: AppConfig | null;
  status: AiStatus;
  message?: string;
  error?: string | null;
  onRun: (provider: string, redact: boolean) => void;
}

/** Offered after the pattern pass. Nothing is sent to an AI service until the user clicks Run. */
export function AiPanel({ config, status, message, error, onRun }: Props) {
  const ids = { prov: useId(), red: useId() };
  const providers = (config?.providers ?? []).filter((p) => p.id !== "none");
  const [provider, setProvider] = useState<string>("");
  const [redact, setRedact] = useState(config?.redact_default ?? true);
  const chosen = provider || config?.ai_default_provider || providers.find((p) => p.configured)?.id || "";
  const info = providers.find((p) => p.id === chosen);
  const busy = status === "running";

  if (config && !config.ai_available) {
    return (
      <Card>
        <div className="flex gap-3 p-5">
          <Icon.Info className="mt-0.5 text-subtle" />
          <p className="text-subtle">
            This is the pattern-library result. An AI-written analysis is not available because no AI provider is set up on the server.
          </p>
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <div className="p-5 sm:p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl">
            <h2 className="text-[15px] font-semibold">Need a deeper write-up?</h2>
            <p className="mt-1 text-subtle">
              What you see below came from the pattern library alone, and no log data left the server. If it is not enough, an AI model can read the same
              evidence and explain the cause in plain English, weigh the alternatives and give tailored fix steps.
            </p>
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label htmlFor={ids.prov} className="mb-1 block text-xs font-semibold">
                AI provider
              </label>
              <select
                id={ids.prov}
                value={chosen}
                disabled={busy}
                onChange={(e) => setProvider(e.target.value)}
                className="h-9 rounded-md border border-lineStrong bg-surface px-2 text-sm"
              >
                {providers.map((p) => (
                  <option key={p.id} value={p.id} disabled={!p.configured}>
                    {p.label}
                    {p.model && p.configured ? ` (${p.model})` : ""}
                    {!p.configured ? " - not set up" : ""}
                  </option>
                ))}
              </select>
            </div>
            <Button variant="primary" className="h-9 px-4" disabled={busy || !chosen} onClick={() => onRun(chosen, redact)}>
              {busy ? (
                <>
                  <Icon.Spinner /> Analysing
                </>
              ) : (
                "Add AI analysis"
              )}
            </Button>
          </div>
        </div>

        <label htmlFor={ids.red} className="mt-4 flex items-start gap-2 text-sm">
          <input id={ids.red} type="checkbox" checked={redact} disabled={busy} onChange={(e) => setRedact(e.target.checked)} className="mt-0.5 h-4 w-4 accent-[var(--brand)]" />
          <span>Remove passwords, tokens, emails and user names before sending</span>
        </label>
        <p className="mt-2 flex items-start gap-2 text-xs text-subtle">
          <Icon.Info className="mt-0.5" />
          <span>
            Clicking the button sends the findings and the surrounding log lines (not your whole files) to {info?.label ?? "the AI provider"}. Nothing is stored
            by this website either way.
          </span>
        </p>

        {busy && (
          <p className="mt-3 text-sm text-subtle" role="status" aria-live="polite">
            {message || "Working"}. This usually takes between 10 seconds and 2 minutes.
          </p>
        )}
        {status === "error" && error && (
          <p className="mt-3 flex items-start gap-2 text-sm text-danger" role="alert">
            <Icon.Alert className="mt-0.5" /> {error} The pattern result above is still valid.
          </p>
        )}
      </div>
    </Card>
  );
}
