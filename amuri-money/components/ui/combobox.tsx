"use client";

import * as React from "react";
import { ChevronDownIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";

export type ComboboxOption = { id: string; name: string };

type Props = {
  value: string | null;
  onChange: (value: string | null) => void;
  options: ComboboxOption[];
  noneLabel?: string;
  placeholder?: string;
  searchPlaceholder?: string;
  disabled?: boolean;
  className?: string;
  id?: string;
  onCreate?: (name: string) => Promise<ComboboxOption>;
  onCreateError?: (err: unknown) => void;
};

export function Combobox({
  value,
  onChange,
  options,
  noneLabel = "—",
  placeholder,
  searchPlaceholder = "Buscar ou criar...",
  disabled,
  className,
  id,
  onCreate,
  onCreateError,
}: Props) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [activeIdx, setActiveIdx] = React.useState(0);
  const [busy, setBusy] = React.useState(false);
  const rootRef = React.useRef<HTMLDivElement>(null);

  const selected = value ? options.find((o) => o.id === value) : null;
  const triggerLabel = selected?.name ?? (placeholder ?? noneLabel);

  const q = query.trim().toLowerCase();
  const filtered = q
    ? options.filter((o) => o.name.toLowerCase().includes(q))
    : options;
  const exactMatch = options.some(
    (o) => o.name.trim().toLowerCase() === q,
  );

  type Item =
    | { kind: "none" }
    | { kind: "existing"; id: string; label: string }
    | { kind: "create"; name: string };

  const items: Item[] = [];
  if (!q) items.push({ kind: "none" });
  for (const o of filtered)
    items.push({ kind: "existing", id: o.id, label: o.name });
  if (q && !exactMatch && onCreate)
    items.push({ kind: "create", name: query.trim() });

  const safeIdx = Math.min(activeIdx, Math.max(items.length - 1, 0));

  React.useEffect(() => {
    if (!open) return;
    function handleClickOutside(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        closePanel();
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  function openPanel() {
    setQuery("");
    setActiveIdx(0);
    setOpen(true);
  }

  function closePanel() {
    setOpen(false);
  }

  async function pick(item: Item) {
    if (item.kind === "none") {
      onChange(null);
      closePanel();
    } else if (item.kind === "existing") {
      onChange(item.id);
      closePanel();
    } else if (onCreate) {
      setBusy(true);
      try {
        const created = await onCreate(item.name);
        onChange(created.id);
        closePanel();
      } catch (err) {
        onCreateError?.(err);
      } finally {
        setBusy(false);
      }
    }
  }

  return (
    <div ref={rootRef} className={cn("relative", className)}>
      <button
        id={id}
        type="button"
        disabled={disabled}
        onClick={() => (open ? closePanel() : openPanel())}
        className={cn(
          "flex h-8 w-full items-center justify-between gap-1.5 rounded-lg border border-input bg-transparent py-1 pr-2 pl-2.5 text-sm whitespace-nowrap transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-input/30 dark:hover:bg-input/50",
          !selected && "text-muted-foreground",
        )}
      >
        <span className="line-clamp-1 text-left">{triggerLabel}</span>
        <ChevronDownIcon className="size-4 shrink-0 text-muted-foreground" />
      </button>
      {open ? (
        <div className="absolute top-full left-0 z-50 mt-1 flex w-full min-w-56 flex-col rounded-lg bg-popover text-popover-foreground shadow-md ring-1 ring-foreground/10">
          <div className="p-1">
            <Input
              type="text"
              autoFocus
              value={query}
              disabled={busy}
              placeholder={searchPlaceholder}
              onChange={(e) => {
                setQuery(e.currentTarget.value);
                setActiveIdx(0);
              }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setActiveIdx((i) => Math.min(i + 1, items.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setActiveIdx((i) => Math.max(i - 1, 0));
                } else if (e.key === "Enter") {
                  e.preventDefault();
                  const it = items[safeIdx];
                  if (it) pick(it);
                } else if (e.key === "Escape") {
                  e.preventDefault();
                  closePanel();
                }
              }}
            />
          </div>
          <div className="max-h-60 overflow-y-auto p-1 pt-0">
            {items.length === 0 ? (
              <div className="px-2 py-1.5 text-sm text-muted-foreground">
                Nenhum resultado.
              </div>
            ) : (
              items.map((it, i) => {
                const isActive = i === safeIdx;
                const label =
                  it.kind === "none"
                    ? noneLabel
                    : it.kind === "existing"
                      ? it.label
                      : `Criar "${it.name}"`;
                return (
                  <button
                    key={it.kind === "existing" ? it.id : it.kind + i}
                    type="button"
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => pick(it)}
                    className={cn(
                      "w-full text-left px-2 py-1.5 text-sm rounded-md",
                      isActive ? "bg-accent text-accent-foreground" : "",
                      it.kind === "create"
                        ? "text-muted-foreground italic"
                        : "",
                    )}
                  >
                    {label}
                  </button>
                );
              })
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
