"use client";

import { useEffect, useState } from "react";
import { Icon } from "./ui";

type Choice = "system" | "light" | "dark";
function apply(choice: Choice) {
  const dark = choice === "dark" || (choice === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
}

export function ThemeToggle() {
  const [choice, setChoice] = useState<Choice>("system");

  useEffect(() => {
    let saved: Choice = "system";
    try {
      const v = localStorage.getItem("theme");
      if (v === "light" || v === "dark") saved = v;
    } catch {
      /* storage blocked */
    }
    setChoice(saved);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => saved === "system" && apply("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const set = (next: Choice) => {
    setChoice(next);
    apply(next);
    try {
      if (next === "system") localStorage.removeItem("theme");
      else localStorage.setItem("theme", next);
    } catch {
      /* storage blocked */
    }
  };

  const items: { id: Choice; label: string; icon: React.ReactNode }[] = [
    { id: "system", label: "Match system", icon: <Icon.Monitor /> },
    { id: "light", label: "Light", icon: <Icon.Sun /> },
    { id: "dark", label: "Dark", icon: <Icon.Moon /> },
  ];

  return (
    <div role="radiogroup" aria-label="Colour theme" className="inline-flex rounded-md border border-line bg-surface p-0.5">
      {items.map((it) => (
        <button
          key={it.id}
          type="button"
          role="radio"
          aria-checked={choice === it.id}
          aria-label={it.label}
          title={it.label}
          onClick={() => set(it.id)}
          className={`flex h-7 w-8 items-center justify-center rounded ${
            choice === it.id ? "bg-brandSoft text-brand" : "text-subtle hover:bg-surface2"
          }`}
        >
          {it.icon}
        </button>
      ))}
    </div>
  );
}
