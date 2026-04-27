import {
  currentYearMonth,
  formatCurrency,
  parseMonthParam,
} from "@/lib/format";
import { getIuguMonthTotals } from "@/lib/gateways/iugu";
import {
  getStripeBooksMonthTotals,
  getStripeMonthTotals,
} from "@/lib/gateways/stripe";
import { ensureGatewayCategories } from "@/lib/gateways/ensure-categories";
import { ensureForeverRecurrences } from "@/lib/recurrences/ensure-forever";
import {
  getCachedCategories,
  getCachedCostCenters,
  getCachedMonthRows,
  getCachedMonthTotals,
} from "@/lib/queries/page-data";
import {
  getProjectedMonthDelta,
  monthsBetween,
} from "@/lib/queries/month-projection";
import { TransactionsList, type Row } from "./transactions-list";
import { MonthNavigator } from "./month-navigator";
import { TotalsCards } from "./totals-cards";
import { Filters, type TypeFilter } from "./filters";
import { NewTransactionDialog } from "./new-transaction-dialog";

type SearchParams = { mes?: string; tipo?: string; q?: string };

function parseTipo(raw: string | undefined): TypeFilter {
  if (raw === "receita" || raw === "despesa") return raw;
  return "todos";
}

type IuguTotals = Awaited<ReturnType<typeof getIuguMonthTotals>>;
type StripeTotals = Awaited<ReturnType<typeof getStripeMonthTotals>>;
type StripeBooksTotals = Awaited<ReturnType<typeof getStripeBooksMonthTotals>>;

function buildGatewayRows(
  year: number,
  month: number,
  iugu: IuguTotals,
  stripe: StripeTotals,
  books: StripeBooksTotals,
): Row[] {
  const pad = (n: number) => String(n).padStart(2, "0");
  const date = `${year}-${pad(month)}-01`;
  const defs: Array<Row & { virtual: true }> = [
    {
      id: `__virtual:iugu:recebido:${year}-${pad(month)}`,
      date,
      description: "Iugu — já recebido neste mês",
      amount: iugu.recebido.total,
      type: "receita",
      paid: true,
      categoryId: null,
      categoryName: "Recebimentos Iugu",
      costCenterId: null,
      costCenterName: null,
      recurrenceId: null,
      parcelNumber: null,
      totalParcels: null,
      dayOfMonth: null,
      virtual: true,
      virtualDetail: { kind: "iugu", items: iugu.recebido.items },
    },
    {
      id: `__virtual:iugu:aReceber:${year}-${pad(month)}`,
      date,
      description: "Iugu — a receber neste mês",
      amount: iugu.aReceber.total,
      type: "receita",
      paid: false,
      categoryId: null,
      categoryName: "Recebimentos Iugu",
      costCenterId: null,
      costCenterName: null,
      recurrenceId: null,
      parcelNumber: null,
      totalParcels: null,
      dayOfMonth: null,
      virtual: true,
      virtualDetail: { kind: "iugu", items: iugu.aReceber.items },
    },
    {
      id: `__virtual:stripe:recebido:${year}-${pad(month)}`,
      date,
      description: "Stripe — já recebido neste mês",
      amount: stripe.recebido.total,
      type: "receita",
      paid: true,
      categoryId: null,
      categoryName: "Recebimentos Stripe",
      costCenterId: null,
      costCenterName: null,
      recurrenceId: null,
      parcelNumber: null,
      totalParcels: null,
      dayOfMonth: null,
      virtual: true,
      virtualDetail: { kind: "stripe", items: stripe.recebido.items },
    },
    {
      id: `__virtual:stripe:aReceber:${year}-${pad(month)}`,
      date,
      description: "Stripe — a receber neste mês",
      amount: stripe.aReceber.total,
      type: "receita",
      paid: false,
      categoryId: null,
      categoryName: "Recebimentos Stripe",
      costCenterId: null,
      costCenterName: null,
      recurrenceId: null,
      parcelNumber: null,
      totalParcels: null,
      dayOfMonth: null,
      virtual: true,
      virtualDetail: { kind: "stripe", items: stripe.aReceber.items },
    },
    {
      id: `__virtual:books:recebido:${year}-${pad(month)}`,
      date,
      description: "Livros — já recebidos neste mês",
      amount: books.recebido.total,
      type: "receita",
      paid: true,
      categoryId: null,
      categoryName: "Recebimentos Livros",
      costCenterId: null,
      costCenterName: null,
      recurrenceId: null,
      parcelNumber: null,
      totalParcels: null,
      dayOfMonth: null,
      virtual: true,
      virtualDetail: { kind: "stripe-books", items: books.recebido.items },
    },
    {
      id: `__virtual:books:aReceber:${year}-${pad(month)}`,
      date,
      description: "Livros — a receber neste mês",
      amount: books.aReceber.total,
      type: "receita",
      paid: false,
      categoryId: null,
      categoryName: "Recebimentos Livros",
      costCenterId: null,
      costCenterName: null,
      recurrenceId: null,
      parcelNumber: null,
      totalParcels: null,
      dayOfMonth: null,
      virtual: true,
      virtualDetail: { kind: "stripe-books", items: books.aReceber.items },
    },
  ];
  return defs.filter((d) => d.amount > 0);
}

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const sp = await searchParams;
  const { year, month } = parseMonthParam(sp.mes);
  const tipo = parseTipo(sp.tipo);
  const q = (sp.q ?? "").trim();

  void ensureGatewayCategories();
  void ensureForeverRecurrences();

  const today = currentYearMonth();
  const viewIsFuture =
    year > today.year || (year === today.year && month > today.month);
  const carryMonths = viewIsFuture
    ? monthsBetween(today.year, today.month, year, month)
    : [];

  const [totalsRow, dbRows, cats, ccs, iugu, stripe, books, carryDeltas] =
    await Promise.all([
      getCachedMonthTotals(year, month),
      getCachedMonthRows(year, month, tipo, q),
      getCachedCategories(),
      getCachedCostCenters(),
      getIuguMonthTotals(year, month),
      getStripeMonthTotals(year, month),
      getStripeBooksMonthTotals(year, month),
      Promise.all(
        carryMonths.map((m) => getProjectedMonthDelta(m.year, m.month)),
      ),
    ]);
  const saldoInicial = carryDeltas.reduce((s, x) => s + x, 0);

  const virtualRows = buildGatewayRows(year, month, iugu, stripe, books);
  const visibleVirtual = q || tipo === "despesa" ? [] : virtualRows;

  const rows: Row[] = [...visibleVirtual, ...(dbRows as Row[])];

  const recebido =
    (totalsRow?.recebido ?? 0) +
    iugu.recebido.total +
    stripe.recebido.total +
    books.recebido.total;
  const aReceber =
    (totalsRow?.aReceber ?? 0) +
    iugu.aReceber.total +
    stripe.aReceber.total +
    books.aReceber.total;
  const pago = totalsRow?.pago ?? 0;
  const aPagar = totalsRow?.aPagar ?? 0;
  const saldoRealizado = recebido - pago;
  const saldoProjetado = saldoInicial + recebido + aReceber - pago - aPagar;
  const saldoPrincipal = viewIsFuture ? saldoInicial : saldoRealizado;

  const baseParams = new URLSearchParams();
  if (tipo !== "todos") baseParams.set("tipo", tipo);
  if (q) baseParams.set("q", q);

  const gatewayError = iugu.error || stripe.error || books.error;

  return (
    <div className="space-y-8">
      <section className="card-soft p-6 md:p-8">
        <div className="flex flex-col md:flex-row md:items-center gap-6 md:gap-10">
          <div className="space-y-1.5">
            <div className="text-xs uppercase tracking-wider text-muted-foreground">
              {viewIsFuture ? "Saldo inicial" : "Saldo atual"}
            </div>
            <div
              className={`text-4xl font-semibold tabular-nums tracking-tight ${
                saldoPrincipal >= 0 ? "text-emerald-700" : "text-rose-700"
              }`}
            >
              {formatCurrency(saldoPrincipal)}
            </div>
            <div className="text-sm text-muted-foreground">
              Saldo projetado para o fim do mês:{" "}
              <span className="tabular-nums font-medium text-foreground">
                {formatCurrency(saldoProjetado)}
              </span>
            </div>
          </div>
          <div className="flex flex-wrap md:ml-auto items-center gap-3">
            <MonthNavigator
              year={year}
              month={month}
              baseParams={baseParams}
            />
          </div>
        </div>
      </section>

      <TotalsCards
        recebido={recebido}
        aReceber={aReceber}
        pago={pago}
        aPagar={aPagar}
      />

      {gatewayError ? (
        <div className="text-xs text-muted-foreground">
          Algum gateway falhou ao responder e foi contado como R$ 0.
          {iugu.error ? ` Iugu: ${iugu.error}.` : ""}
          {stripe.error ? ` Stripe: ${stripe.error}.` : ""}
        </div>
      ) : null}

      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <Filters tipo={tipo} q={q} />
        <NewTransactionDialog categories={cats} costCenters={ccs} />
      </div>

      <TransactionsList rows={rows} categories={cats} costCenters={ccs} />
    </div>
  );
}
