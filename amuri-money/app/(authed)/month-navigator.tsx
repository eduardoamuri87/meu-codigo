import Link from "next/link";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { addMonths, formatMonthParam } from "@/lib/format";
import { buttonVariants } from "@/components/ui/button";
import { MonthPicker } from "./month-picker";

export function MonthNavigator({
  year,
  month,
  baseParams,
}: {
  year: number;
  month: number;
  baseParams: URLSearchParams;
}) {
  const prev = addMonths(year, month, -1);
  const next = addMonths(year, month, 1);

  function hrefFor(y: number, m: number) {
    const params = new URLSearchParams(baseParams);
    params.set("mes", formatMonthParam(y, m));
    return `/?${params.toString()}`;
  }

  return (
    <div className="flex items-center gap-2">
      <Link
        href={hrefFor(prev.year, prev.month)}
        className={buttonVariants({ variant: "ghost", size: "icon" })}
        aria-label="Mês anterior"
      >
        <ChevronLeft className="h-4 w-4" />
      </Link>
      <MonthPicker
        year={year}
        month={month}
        baseParams={baseParams.toString()}
      />
      <Link
        href={hrefFor(next.year, next.month)}
        className={buttonVariants({ variant: "ghost", size: "icon" })}
        aria-label="Próximo mês"
      >
        <ChevronRight className="h-4 w-4" />
      </Link>
    </div>
  );
}
