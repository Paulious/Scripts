import { ThemeToggle } from "./ThemeToggle";
import { Icon } from "./ui";

export function Header({ onHome, backend }: { onHome: () => void; backend: "checking" | "online" | "offline" }) {
  return (
    <header className="sticky top-0 z-20 border-b border-line bg-surface/95 backdrop-blur">
      <div className="mx-auto flex h-12 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
        <button type="button" onClick={onHome} className="flex items-center gap-2.5 rounded-md" aria-label="Deployment Log Analyzer, start over">
          <span className="grid h-7 w-7 place-items-center rounded-md bg-brand text-onBrand">
            <Icon.Shield className="h-4 w-4" />
          </span>
          <span className="text-[15px] font-semibold">Deployment Log Analyzer</span>
        </button>
        <div className="flex items-center gap-3">
          <span className="hidden items-center gap-1.5 text-xs text-subtle sm:flex" role="status">
            <span
              className={`h-2 w-2 rounded-full ${backend === "online" ? "bg-ok" : backend === "offline" ? "bg-danger" : "bg-faint"}`}
              aria-hidden="true"
            />
            {backend === "online" ? "Service ready" : backend === "offline" ? "Service unreachable" : "Connecting"}
          </span>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
