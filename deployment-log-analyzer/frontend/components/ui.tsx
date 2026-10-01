"use client";

import { useState, type ReactNode } from "react";

type IconProps = { className?: string };
const base = "shrink-0";

function svg(path: ReactNode, { className = "" }: IconProps, size = 16) {
  return (
    <svg
      className={`${base} ${className}`}
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {path}
    </svg>
  );
}

export const Icon = {
  Upload: (p: IconProps) => svg(<><path d="M10 13V3m0 0L6 7m4-4 4 4" /><path d="M3 13v3a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-3" /></>, p),
  Check: (p: IconProps) => svg(<path d="m4 10.5 4 4 8-9" />, p),
  Close: (p: IconProps) => svg(<path d="m5 5 10 10M15 5 5 15" />, p),
  Copy: (p: IconProps) => svg(<><rect x="7" y="7" width="9" height="10" rx="1.5" /><path d="M13 7V4.5A1.5 1.5 0 0 0 11.5 3h-6A1.5 1.5 0 0 0 4 4.5v8A1.5 1.5 0 0 0 5.5 14H7" /></>, p),
  Download: (p: IconProps) => svg(<><path d="M10 3v10m0 0 4-4m-4 4L6 9" /><path d="M3 13v3a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-3" /></>, p),
  File: (p: IconProps) => svg(<><path d="M5 2.5h6l4 4V17a.5.5 0 0 1-.5.5h-9A.5.5 0 0 1 5 17V3a.5.5 0 0 1 .5-.5Z" /><path d="M11 2.5V7h4" /></>, p),
  Archive: (p: IconProps) => svg(<><rect x="3" y="3.5" width="14" height="4" rx="1" /><path d="M4.5 7.5V16a.5.5 0 0 0 .5.5h10a.5.5 0 0 0 .5-.5V7.5M8 11h4" /></>, p),
  Chevron: (p: IconProps) => svg(<path d="m7 4 6 6-6 6" />, p),
  Sun: (p: IconProps) => svg(<><circle cx="10" cy="10" r="3.5" /><path d="M10 2v2m0 12v2M2 10h2m12 0h2M4.3 4.3l1.4 1.4m8.6 8.6 1.4 1.4m0-11.4-1.4 1.4M5.7 14.3l-1.4 1.4" /></>, p),
  Moon: (p: IconProps) => svg(<path d="M16.5 11.5A6.5 6.5 0 0 1 8.5 3.5a6.5 6.5 0 1 0 8 8Z" />, p),
  Monitor: (p: IconProps) => svg(<><rect x="2.5" y="3.5" width="15" height="10" rx="1.5" /><path d="M7 17h6M10 13.5V17" /></>, p),
  Shield: (p: IconProps) => svg(<path d="M10 2.5 4 4.5v5c0 3.5 2.5 6.2 6 8 3.5-1.8 6-4.5 6-8v-5l-6-2Z" />, p),
  Alert: (p: IconProps) => svg(<><path d="M10 3 2 17h16L10 3Z" /><path d="M10 8.5v3.5m0 2.2v.1" /></>, p),
  Info: (p: IconProps) => svg(<><circle cx="10" cy="10" r="7.5" /><path d="M10 9v5m0-7.5v.1" /></>, p),
  Spinner: ({ className = "" }: IconProps) => (
    <svg className={`${base} animate-spin ${className}`} width="16" height="16" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <circle cx="10" cy="10" r="7.5" stroke="currentColor" strokeOpacity=".25" strokeWidth="2.5" />
      <path d="M17.5 10A7.5 7.5 0 0 0 10 2.5" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  ),
};

export function Card({ children, className = "", as: Tag = "section" }: { children: ReactNode; className?: string; as?: "section" | "div" | "article" }) {
  return <Tag className={`rounded-lg border border-line bg-surface shadow-[0_1px_2px_rgba(0,0,0,0.04)] ${className}`}>{children}</Tag>;
}

export function CardHeader({ title, aside, sub }: { title: string; aside?: ReactNode; sub?: string }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-3.5">
      <div>
        <h2 className="text-[15px] font-semibold leading-5">{title}</h2>
        {sub && <p className="mt-0.5 text-xs text-subtle">{sub}</p>}
      </div>
      {aside}
    </div>
  );
}

const tones = {
  neutral: "bg-surface2 text-subtle border-line",
  brand: "bg-brandSoft text-brand border-transparent",
  danger: "bg-dangerSoft text-danger border-transparent",
  warn: "bg-warnSoft text-warn border-transparent",
  ok: "bg-okSoft text-ok border-transparent",
} as const;

export function Badge({ tone = "neutral", children, title }: { tone?: keyof typeof tones; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function Button({
  children,
  onClick,
  variant = "secondary",
  disabled,
  type = "button",
  className = "",
  ...rest
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "ghost";
  disabled?: boolean;
  type?: "button" | "submit";
  className?: string;
} & Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "onClick" | "type" | "className" | "children">) {
  const styles = {
    primary: "bg-brand text-onBrand hover:bg-brandHover border-transparent",
    secondary: "bg-surface text-fg border-lineStrong hover:bg-surface2",
    ghost: "bg-transparent text-fg border-transparent hover:bg-surface2",
  }[variant];
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex h-8 items-center justify-center gap-1.5 rounded-md border px-3 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${styles} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}

export function CopyButton({ text, label = "Copy", className = "" }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard blocked: nothing useful to do */
        }
      }}
      className={`inline-flex h-7 items-center gap-1 rounded-md border border-line bg-surface px-2 text-xs font-medium text-subtle hover:bg-surface2 hover:text-fg ${className}`}
      aria-label={done ? "Copied" : label}
    >
      {done ? <Icon.Check className="text-ok" /> : <Icon.Copy />}
      <span aria-live="polite">{done ? "Copied" : label}</span>
    </button>
  );
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: string; tone?: "danger" | "ok" }) {
  return (
    <div className="min-w-0 px-5 py-4">
      <div className="text-xs font-medium text-subtle">{label}</div>
      <div className={`mt-1 truncate text-2xl font-semibold leading-8 ${tone === "danger" ? "text-danger" : tone === "ok" ? "text-ok" : ""}`}>{value}</div>
      {sub && <div className="mt-0.5 truncate text-xs text-faint">{sub}</div>}
    </div>
  );
}
