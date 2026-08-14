import "server-only";
import { inArray } from "drizzle-orm";
import { db } from "@/lib/db";
import { monthSnapshots } from "@/lib/db/schema";
import { getIuguMonthTotals } from "@/lib/gateways/iugu";
import {
  getStripeBooksMonthTotals,
  getStripeMonthTotals,
} from "@/lib/gateways/stripe";
import { currentYearMonth } from "@/lib/format";
import { getCachedMonthTotals } from "@/lib/queries/page-data";

export type YearMonth = { year: number; month: number };

function snapshotId(year: number, month: number): string {
  return `${year}-${String(month).padStart(2, "0")}`;
}

/** Um mês está fechado quando é estritamente anterior ao mês corrente. */
function isClosed(year: number, month: number, today: YearMonth): boolean {
  return year < today.year || (year === today.year && month < today.month);
}

/**
 * Parte de gateway do delta do mês: tudo que Iugu, Stripe e Livros somam,
 * recebido e a receber. Custa de 3 a 5 chamadas de API.
 */
async function computeGatewayDelta(
  year: number,
  month: number,
): Promise<number> {
  const [stripe, iugu, books] = await Promise.all([
    getStripeMonthTotals(year, month),
    getIuguMonthTotals(year, month),
    getStripeBooksMonthTotals(year, month),
  ]);
  // Um gateway que falhou vem zerado com `error` preenchido. Gravar isso como
  // snapshot congelaria o zero para sempre, então quem chama precisa saber.
  const failed = Boolean(stripe.error || iugu.error || books.error);
  const total =
    stripe.recebido.total +
    stripe.aReceber.total +
    iugu.recebido.total +
    iugu.aReceber.total +
    books.recebido.total +
    books.aReceber.total;
  if (failed) throw new Error("gateway falhou; delta não é confiável");
  return total;
}

/** Parte de banco do delta do mês. Sempre ao vivo: editar um mês passado muda. */
async function computeDbDelta(year: number, month: number): Promise<number> {
  const totals = await getCachedMonthTotals(year, month);
  return (
    totals.recebido + totals.aReceber - totals.pago - totals.aPagar
  );
}

/**
 * Deltas acumulados de uma lista de meses, para compor o saldo inicial.
 *
 * Antes isso chamava 3 gateways por mês, em toda carga de página — o custo
 * crescia 3 chamadas a cada mês que passava. Agora os meses fechados vêm de
 * `month_snapshots` numa única query, e só o mês corrente (e futuros) consultam
 * a API. Meses fechados sem snapshot são calculados uma vez e gravados.
 */
export async function getMonthDeltas(months: YearMonth[]): Promise<number[]> {
  if (months.length === 0) return [];

  const today = currentYearMonth();
  const closed = months.filter((m) => isClosed(m.year, m.month, today));

  const stored = new Map<string, number>();
  if (closed.length > 0) {
    const rows = await db
      .select({
        id: monthSnapshots.id,
        gatewayDelta: monthSnapshots.gatewayDelta,
      })
      .from(monthSnapshots)
      .where(
        inArray(
          monthSnapshots.id,
          closed.map((m) => snapshotId(m.year, m.month)),
        ),
      );
    for (const r of rows) stored.set(r.id, r.gatewayDelta);
  }

  const toPersist: Array<{ id: string; m: YearMonth; delta: number }> = [];

  const deltas = await Promise.all(
    months.map(async (m) => {
      const id = snapshotId(m.year, m.month);
      const dbDelta = await computeDbDelta(m.year, m.month);

      const cached = stored.get(id);
      if (cached !== undefined) return dbDelta + cached;

      // Mês corrente/futuro, ou mês fechado ainda sem snapshot.
      let gatewayDelta: number;
      try {
        gatewayDelta = await computeGatewayDelta(m.year, m.month);
      } catch {
        // Gateway indisponível: conta como zero nesta renderização, mas não
        // grava snapshot — a próxima carga tenta de novo.
        return dbDelta;
      }

      if (isClosed(m.year, m.month, today)) {
        toPersist.push({ id, m, delta: gatewayDelta });
      }
      return dbDelta + gatewayDelta;
    }),
  );

  if (toPersist.length > 0) {
    const now = Date.now();
    try {
      await db
        .insert(monthSnapshots)
        .values(
          toPersist.map(({ id, m, delta }) => ({
            id,
            year: m.year,
            month: m.month,
            gatewayDelta: delta,
            computedAt: now,
          })),
        )
        .onConflictDoNothing();
    } catch (e) {
      // Snapshot é otimização, não pode derrubar a página.
      console.error("[month-projection] gravar snapshot falhou:", e);
    }
  }

  return deltas;
}

/** Descarta todos os snapshots, forçando recálculo na próxima carga. */
export async function clearMonthSnapshots(): Promise<void> {
  await db.delete(monthSnapshots);
}

export function monthsBetween(
  fromYear: number,
  fromMonth: number,
  toYearExclusive: number,
  toMonthExclusive: number,
): YearMonth[] {
  const out: YearMonth[] = [];
  let y = fromYear;
  let m = fromMonth;
  while (y < toYearExclusive || (y === toYearExclusive && m < toMonthExclusive)) {
    out.push({ year: y, month: m });
    if (m === 12) {
      y += 1;
      m = 1;
    } else {
      m += 1;
    }
  }
  return out;
}
