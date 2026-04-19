import Link from "next/link";
import { and, asc, desc, eq, gte, like, lt, sql } from "drizzle-orm";
import { Plus } from "lucide-react";
import { db } from "@/lib/db";
import { categories, recurrences, transactions } from "@/lib/db/schema";
import { buttonVariants } from "@/components/ui/button";
import {
  formatCurrency,
  monthRange,
  parseMonthParam,
} from "@/lib/format";
import { TransactionsList, type Row } from "./transactions-list";
import { MonthNavigator } from "./month-navigator";
import { TotalsCards } from "./totals-cards";
import { Filters, type TypeFilter } from "./filters";
import { ProgressRing } from "./progress-ring";

type SearchParams = { mes?: string; tipo?: string; q?: string };

function parseTipo(raw: string | undefined): TypeFilter {
  if (raw === "receita" || raw === "despesa") return raw;
  return "todos";
}

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const sp = await searchParams;
  const { year, month } = parseMonthParam(sp.mes);
  const { start, end } = monthRange(year, month);
  const tipo = parseTipo(sp.tipo);
  const q = (sp.q ?? "").trim();

  const monthWhere = and(
    gte(transactions.date, start),
    lt(transactions.date, end),
  );

  const listWhere = and(
    monthWhere,
    tipo === "todos" ? undefined : eq(transactions.type, tipo),
    q
      ? like(sql`LOWER(${transactions.description})`, `%${q.toLowerCase()}%`)
      : undefined,
  );

  const [totalsRow] = await db
    .select({
      recebido: sql<number>`COALESCE(SUM(CASE WHEN ${transactions.type} = 'receita' AND ${transactions.paid} = 1 THEN ${transactions.amount} ELSE 0 END), 0)`,
      aReceber: sql<number>`COALESCE(SUM(CASE WHEN ${transactions.type} = 'receita' AND ${transactions.paid} = 0 THEN ${transactions.amount} ELSE 0 END), 0)`,
      pago: sql<number>`COALESCE(SUM(CASE WHEN ${transactions.type} = 'despesa' AND ${transactions.paid} = 1 THEN ${transactions.amount} ELSE 0 END), 0)`,
      aPagar: sql<number>`COALESCE(SUM(CASE WHEN ${transactions.type} = 'despesa' AND ${transactions.paid} = 0 THEN ${transactions.amount} ELSE 0 END), 0)`,
    })
    .from(transactions)
    .where(monthWhere);

  const rows = await db
    .select({
      id: transactions.id,
      date: transactions.date,
      description: transactions.description,
      amount: transactions.amount,
      type: transactions.type,
      paid: transactions.paid,
      categoryId: transactions.categoryId,
      categoryName: categories.name,
      recurrenceId: transactions.recurrenceId,
      parcelNumber: transactions.parcelNumber,
      totalParcels: recurrences.totalParcels,
    })
    .from(transactions)
    .leftJoin(categories, eq(transactions.categoryId, categories.id))
    .leftJoin(recurrences, eq(transactions.recurrenceId, recurrences.id))
    .where(listWhere)
    .orderBy(desc(transactions.date), asc(transactions.description));

  const recebido = totalsRow?.recebido ?? 0;
  const aReceber = totalsRow?.aReceber ?? 0;
  const pago = totalsRow?.pago ?? 0;
  const aPagar = totalsRow?.aPagar ?? 0;
  const saldoRealizado = recebido - pago;
  const saldoProjetado = recebido + aReceber - pago - aPagar;
  const totalMovimentado = recebido + aReceber + pago + aPagar;
  const liquidado = totalMovimentado === 0
    ? 0
    : (recebido + pago) / totalMovimentado;

  const baseParams = new URLSearchParams();
  if (tipo !== "todos") baseParams.set("tipo", tipo);
  if (q) baseParams.set("q", q);

  return (
    <div className="space-y-8">
      <section className="card-soft p-6 md:p-8">
        <div className="flex flex-col md:flex-row md:items-center gap-6 md:gap-10">
          <div className="flex items-center gap-6">
            <ProgressRing value={liquidado} size={108} stroke={10} />
            <div className="space-y-1.5">
              <div className="text-xs uppercase tracking-wider text-muted-foreground">
                Saldo realizado
              </div>
              <div
                className={`text-4xl font-semibold tabular-nums tracking-tight ${
                  saldoRealizado >= 0 ? "text-emerald-700" : "text-rose-700"
                }`}
              >
                {formatCurrency(saldoRealizado)}
              </div>
              <div className="text-sm text-muted-foreground">
                Projetado no mês:{" "}
                <span className="tabular-nums font-medium text-foreground">
                  {formatCurrency(saldoProjetado)}
                </span>
              </div>
            </div>
          </div>
          <div className="flex flex-wrap md:ml-auto items-center gap-3">
            <MonthNavigator
              year={year}
              month={month}
              baseParams={baseParams}
            />
            <Link
              href="/transacoes/nova"
              className={buttonVariants()}
            >
              <Plus className="h-4 w-4" />
              Nova transação
            </Link>
          </div>
        </div>
      </section>

      <TotalsCards
        recebido={recebido}
        aReceber={aReceber}
        pago={pago}
        aPagar={aPagar}
      />

      <Filters tipo={tipo} q={q} />

      <TransactionsList rows={rows as Row[]} />
    </div>
  );
}
