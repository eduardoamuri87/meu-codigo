import "server-only";
import { getIuguMonthTotals } from "@/lib/gateways/iugu";
import {
  getStripeBooksMonthTotals,
  getStripeMonthTotals,
} from "@/lib/gateways/stripe";
import { getCachedMonthTotals } from "@/lib/queries/page-data";

export async function getProjectedMonthDelta(
  year: number,
  month: number,
): Promise<number> {
  const [totals, stripe, iugu, books] = await Promise.all([
    getCachedMonthTotals(year, month),
    getStripeMonthTotals(year, month),
    getIuguMonthTotals(year, month),
    getStripeBooksMonthTotals(year, month),
  ]);
  const receita =
    totals.recebido +
    totals.aReceber +
    stripe.recebido.total +
    stripe.aReceber.total +
    iugu.recebido.total +
    iugu.aReceber.total +
    books.recebido.total +
    books.aReceber.total;
  const despesa = totals.pago + totals.aPagar;
  return receita - despesa;
}

export function monthsBetween(
  fromYear: number,
  fromMonth: number,
  toYearExclusive: number,
  toMonthExclusive: number,
): { year: number; month: number }[] {
  const out: { year: number; month: number }[] = [];
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
