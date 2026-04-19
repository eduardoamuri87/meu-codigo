import { ArrowUpRight, Clock, CheckCircle2 } from "lucide-react";
import { formatCurrency } from "@/lib/format";

export function TotalsCards({
  recebido,
  aReceber,
  pago,
  aPagar,
}: {
  recebido: number;
  aReceber: number;
  pago: number;
  aPagar: number;
}) {
  const items = [
    {
      label: "Recebido",
      value: recebido,
      icon: CheckCircle2,
      tone: "emerald",
    },
    {
      label: "A receber",
      value: aReceber,
      icon: ArrowUpRight,
      tone: "emerald-soft",
    },
    {
      label: "Pago",
      value: pago,
      icon: CheckCircle2,
      tone: "rose",
    },
    {
      label: "A pagar",
      value: aPagar,
      icon: Clock,
      tone: "rose-soft",
    },
  ] as const;

  const toneStyles: Record<string, string> = {
    emerald:
      "bg-emerald-500/10 text-emerald-700 ring-emerald-500/20",
    "emerald-soft":
      "bg-emerald-500/5 text-emerald-600 ring-emerald-500/15",
    rose: "bg-rose-500/10 text-rose-700 ring-rose-500/20",
    "rose-soft": "bg-rose-500/5 text-rose-600 ring-rose-500/15",
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <div
            key={item.label}
            className="card-soft p-5 md:p-6 flex flex-col gap-4"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase tracking-wider text-muted-foreground">
                {item.label}
              </span>
              <span
                className={`grid place-items-center size-9 rounded-lg ring-1 ${toneStyles[item.tone]}`}
              >
                <Icon className="h-4 w-4" />
              </span>
            </div>
            <div className="text-2xl font-semibold tabular-nums">
              {formatCurrency(item.value)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

