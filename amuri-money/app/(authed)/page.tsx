import { Suspense } from "react";
import { after } from "next/server";
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
  getMonthDeltas,
  monthsBetween,
  type YearMonth,
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
      parentId: null,
      isParent: false,
      childSum: 0,
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
      parentId: null,
      isParent: false,
      childSum: 0,
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
      parentId: null,
      isParent: false,
      childSum: 0,
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
      parentId: null,
      isParent: false,
      childSum: 0,
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
      parentId: null,
      isParent: false,
      childSum: 0,
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
      parentId: null,
      isParent: false,
      childSum: 0,
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

  // after() em vez de void: essas rotinas de manutenção rodam depois da
  // resposta, sem disputar o event loop e o handle do SQLite com o render.
  after(async () => {
    await ensureGatewayCategories();
    await ensureForeverRecurrences();
  });

  const today = currentYearMonth();
  const viewIsFuture =
    year > today.year || (year === today.year && month > today.month);
  const viewIsPast =
    year < today.year || (year === today.year && month < today.month);
  // Saldo zero em 1º de abril/2026; tudo posterior acumula o delta de cada
  // mês para que saldoInicial(M+1) = saldoFinalProjetado(M) e o "saldo atual"
  // do mês corrente seja saldoInicial + (recebido − pago) realizado.
  const SALDO_GENESIS = { year: 2026, month: 4 };
  const carryMonths = monthsBetween(
    SALDO_GENESIS.year,
    SALDO_GENESIS.month,
    year,
    month,
  );

  // Só o que vem do banco (indexado, já em unstable_cache) bloqueia a casca da
  // página. Tudo que depende de Iugu/Stripe fica dentro de <Suspense> e chega
  // por streaming — com skeleton, nunca com número provisório errado.
  const [cats, ccs] = await Promise.all([
    getCachedCategories(),
    getCachedCostCenters(),
  ]);

  const baseParams = new URLSearchParams();
  if (tipo !== "todos") baseParams.set("tipo", tipo);
  if (q) baseParams.set("q", q);

  return (
    <div className="space-y-8">
      <section className="card-soft p-6 md:p-8">
        <div className="flex flex-col md:flex-row md:items-center gap-6 md:gap-10">
          <Suspense fallback={<SaldoSkeleton viewIsFuture={viewIsFuture} />}>
            <SaldoBlock
              year={year}
              month={month}
              carryMonths={carryMonths}
              viewIsFuture={viewIsFuture}
              viewIsPast={viewIsPast}
            />
          </Suspense>
          <div className="flex flex-wrap md:ml-auto items-center gap-3">
            <MonthNavigator
              year={year}
              month={month}
              baseParams={baseParams}
            />
          </div>
        </div>
      </section>

      <Suspense fallback={<TotalsSkeleton />}>
        <TotalsSection year={year} month={month} />
      </Suspense>

      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <Filters tipo={tipo} q={q} />
        <NewTransactionDialog categories={cats} costCenters={ccs} />
      </div>

      <Suspense fallback={<ListSkeleton />}>
        <TransactionsSection
          year={year}
          month={month}
          tipo={tipo}
          q={q}
          categories={cats}
          costCenters={ccs}
        />
      </Suspense>
    </div>
  );
}

/**
 * Totais de gateway do mês visto. As três chamadas são compartilhadas entre
 * SaldoBlock, TotalsSection e TransactionsSection pelo dedupe de in-flight do
 * withCheckpointCache, então decompor a página em três boundaries não multiplica
 * requisição nenhuma.
 */
async function getGatewayTotals(year: number, month: number) {
  const [iugu, stripe, books] = await Promise.all([
    getIuguMonthTotals(year, month),
    getStripeMonthTotals(year, month),
    getStripeBooksMonthTotals(year, month),
  ]);
  return { iugu, stripe, books };
}

async function SaldoBlock({
  year,
  month,
  carryMonths,
  viewIsFuture,
  viewIsPast,
}: {
  year: number;
  month: number;
  carryMonths: YearMonth[];
  viewIsFuture: boolean;
  viewIsPast: boolean;
}) {
  const [totalsRow, { iugu, stripe, books }, carryDeltas] = await Promise.all([
    getCachedMonthTotals(year, month),
    getGatewayTotals(year, month),
    getMonthDeltas(carryMonths),
  ]);

  const saldoInicial = carryDeltas.reduce((s, x) => s + x, 0);
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
  const saldoAtual = saldoInicial + recebido - pago;
  const saldoProjetado = saldoInicial + recebido + aReceber - pago - aPagar;
  const saldoPrincipal = viewIsFuture ? saldoInicial : saldoAtual;

  return (
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
        {viewIsPast
          ? "Saldo efetivado no fim do mês"
          : "Saldo projetado para o fim do mês"}
        :{" "}
        <span className="tabular-nums font-medium text-foreground">
          {formatCurrency(viewIsPast ? saldoAtual : saldoProjetado)}
        </span>
      </div>
    </div>
  );
}

function SaldoSkeleton({ viewIsFuture }: { viewIsFuture: boolean }) {
  return (
    <div className="space-y-1.5">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">
        {viewIsFuture ? "Saldo inicial" : "Saldo atual"}
      </div>
      <div className="h-10 w-52 animate-pulse rounded bg-muted" />
      <div className="h-5 w-72 animate-pulse rounded bg-muted" />
    </div>
  );
}

async function TotalsSection({
  year,
  month,
}: {
  year: number;
  month: number;
}) {
  const [totalsRow, { iugu, stripe, books }] = await Promise.all([
    getCachedMonthTotals(year, month),
    getGatewayTotals(year, month),
  ]);

  const gatewayError = iugu.error || stripe.error || books.error;

  return (
    <>
      <TotalsCards
        recebido={
          (totalsRow?.recebido ?? 0) +
          iugu.recebido.total +
          stripe.recebido.total +
          books.recebido.total
        }
        aReceber={
          (totalsRow?.aReceber ?? 0) +
          iugu.aReceber.total +
          stripe.aReceber.total +
          books.aReceber.total
        }
        pago={totalsRow?.pago ?? 0}
        aPagar={totalsRow?.aPagar ?? 0}
      />
      {gatewayError ? (
        <div className="mt-3 text-xs text-muted-foreground">
          Algum gateway falhou ao responder e foi contado como R$ 0.
          {iugu.error ? ` Iugu: ${iugu.error}.` : ""}
          {stripe.error ? ` Stripe: ${stripe.error}.` : ""}
        </div>
      ) : null}
    </>
  );
}

function TotalsSkeleton() {
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {[0, 1, 2, 3].map((i) => (
        <div key={i} className="card-soft h-24 animate-pulse bg-muted" />
      ))}
    </div>
  );
}

async function TransactionsSection({
  year,
  month,
  tipo,
  q,
  categories,
  costCenters,
}: {
  year: number;
  month: number;
  tipo: TypeFilter;
  q: string;
  categories: React.ComponentProps<typeof TransactionsList>["categories"];
  costCenters: React.ComponentProps<typeof TransactionsList>["costCenters"];
}) {
  const [dbRows, { iugu, stripe, books }] = await Promise.all([
    getCachedMonthRows(year, month, tipo, q),
    getGatewayTotals(year, month),
  ]);

  const virtualRows = buildGatewayRows(year, month, iugu, stripe, books);
  const visibleVirtual = q || tipo === "despesa" ? [] : virtualRows;
  const rows: Row[] = [...visibleVirtual, ...(dbRows as Row[])];

  return (
    <TransactionsList
      rows={rows}
      categories={categories}
      costCenters={costCenters}
    />
  );
}

function ListSkeleton() {
  return (
    <div className="space-y-2">
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <div key={i} className="h-12 animate-pulse rounded bg-muted" />
      ))}
    </div>
  );
}
