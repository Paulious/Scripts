import type { Confidence } from "@/lib/types";

export function tone(label: Confidence["label"]) {
  return label === "High" ? "ok" : label === "Medium" ? "warn" : "danger";
}

export function ConfidenceRing({ score, label, size = 88 }: { score: number; label: Confidence["label"]; size?: number }) {
  const r = (size - 10) / 2;
  const c = 2 * Math.PI * r;
  const color = `var(--${tone(label)})`;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`Confidence ${score} percent, ${label}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--line)" strokeWidth="8" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - score / 100)}
          style={{ transition: "stroke-dashoffset .6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-semibold leading-6">{score}</span>
        <span className="text-[10px] font-medium uppercase tracking-wide text-subtle">{label}</span>
      </div>
    </div>
  );
}
