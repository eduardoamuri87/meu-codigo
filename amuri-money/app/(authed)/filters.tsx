"use client";

import { useTransition, useMemo, useEffect, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";

export type TypeFilter = "todos" | "receita" | "despesa";

const OPTIONS: Array<{ value: TypeFilter; label: string }> = [
  { value: "todos", label: "Todos" },
  { value: "receita", label: "Receitas" },
  { value: "despesa", label: "Despesas" },
];

export function Filters({
  tipo,
  q,
}: {
  tipo: TypeFilter;
  q: string;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [, startTransition] = useTransition();
  const [searchInput, setSearchInput] = useState(q);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const paramsString = useMemo(() => params.toString(), [params]);

  useEffect(() => {
    setSearchInput(q);
  }, [q]);

  function updateParam(key: string, value: string | null) {
    const sp = new URLSearchParams(paramsString);
    if (value === null || value === "") sp.delete(key);
    else sp.set(key, value);
    const qs = sp.toString();
    startTransition(() => {
      router.replace(qs ? `${pathname}?${qs}` : pathname);
    });
  }

  function selectTipo(v: TypeFilter) {
    updateParam("tipo", v === "todos" ? null : v);
  }

  function onSearchChange(v: string) {
    setSearchInput(v);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      updateParam("q", v.trim() || null);
    }, 250);
  }

  return (
    <div className="flex flex-col sm:flex-row gap-3 sm:items-center">
      <div className="inline-flex rounded-md border bg-muted/40 p-1 w-fit">
        {OPTIONS.map((opt) => (
          <button
            key={opt.value}
            type="button"
            onClick={() => selectTipo(opt.value)}
            className={`px-3 py-1 text-sm rounded transition ${
              tipo === opt.value
                ? "bg-background shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>
      <div className="relative flex-1 sm:max-w-xs">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          value={searchInput}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Buscar por descrição..."
          className="pl-9"
        />
      </div>
    </div>
  );
}
