"use client";

import { useState } from "react";
import Link from "next/link";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Popover } from "@base-ui/react/popover";
import { formatMonthLabel, formatMonthParam } from "@/lib/format";
import { cn } from "@/lib/utils";

const MONTHS_SHORT = [
  "jan", "fev", "mar", "abr", "mai", "jun",
  "jul", "ago", "set", "out", "nov", "dez",
];

export function MonthPicker({
  year,
  month,
  baseParams,
}: {
  year: number;
  month: number;
  baseParams: string;
}) {
  const [open, setOpen] = useState(false);
  const [viewYear, setViewYear] = useState(year);

  function hrefFor(y: number, m: number) {
    const params = new URLSearchParams(baseParams);
    params.set("mes", formatMonthParam(y, m));
    return `/?${params.toString()}`;
  }

  return (
    <Popover.Root
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) setViewYear(year);
      }}
    >
      <Popover.Trigger
        className="min-w-40 text-center font-medium capitalize rounded-md px-2 py-1 hover:bg-muted transition cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {formatMonthLabel(year, month)}
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Positioner sideOffset={6} align="center">
          <Popover.Popup className="z-50 rounded-lg bg-popover text-popover-foreground shadow-md ring-1 ring-foreground/10 p-3 outline-none data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95">
            <div className="flex items-center justify-between mb-3 gap-2">
              <button
                type="button"
                onClick={() => setViewYear((y) => y - 1)}
                aria-label="Ano anterior"
                className="size-7 grid place-items-center rounded-md hover:bg-muted transition cursor-pointer"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <div className="font-medium tabular-nums text-sm">{viewYear}</div>
              <button
                type="button"
                onClick={() => setViewYear((y) => y + 1)}
                aria-label="Próximo ano"
                className="size-7 grid place-items-center rounded-md hover:bg-muted transition cursor-pointer"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
            <div className="grid grid-cols-3 gap-1 w-56">
              {MONTHS_SHORT.map((label, i) => {
                const m = i + 1;
                const isSelected = viewYear === year && m === month;
                return (
                  <Link
                    key={m}
                    href={hrefFor(viewYear, m)}
                    onClick={() => setOpen(false)}
                    className={cn(
                      "rounded-md px-3 py-2 text-sm capitalize text-center transition",
                      isSelected
                        ? "bg-primary text-primary-foreground hover:bg-primary"
                        : "hover:bg-muted",
                    )}
                  >
                    {label}
                  </Link>
                );
              })}
            </div>
          </Popover.Popup>
        </Popover.Positioner>
      </Popover.Portal>
    </Popover.Root>
  );
}
