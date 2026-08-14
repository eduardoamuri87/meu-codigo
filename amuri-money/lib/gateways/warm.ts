import "server-only";
import { currentYearMonth } from "@/lib/format";
import { getIuguMonthTotals } from "./iugu";
import { getStripeBooksMonthTotals, getStripeMonthTotals } from "./stripe";

/**
 * Preenche o cache de gateway fora do caminho de uma request.
 *
 * Medido em produção: a janela de faturas da Iugu custa ~25s por página, custo
 * fixo da API. Mesmo paginando em paralelo, a sincronização fica na casa dos 30
 * a 50s. Isso não pode acontecer dentro de uma request de usuário duas vezes por
 * dia — daí o aquecimento agendado logo após cada checkpoint.
 *
 * Aquece o mês corrente e o seguinte: são os únicos que ainda consultam API
 * depois que os meses fechados viram snapshot em month_snapshots.
 */
export async function warmGateways(reason: string): Promise<void> {
  const startedAt = Date.now();
  const { year, month } = currentYearMonth();
  const next =
    month === 12 ? { year: year + 1, month: 1 } : { year, month: month + 1 };

  const results = await Promise.allSettled([
    getIuguMonthTotals(year, month),
    getStripeMonthTotals(year, month),
    getStripeBooksMonthTotals(year, month),
    getIuguMonthTotals(next.year, next.month),
    getStripeMonthTotals(next.year, next.month),
    getStripeBooksMonthTotals(next.year, next.month),
  ]);

  // Os getters capturam os próprios erros e devolvem `error` preenchido, então
  // conto as duas formas de falha para o log dizer a verdade.
  let failures = 0;
  for (const r of results) {
    if (r.status === "rejected") failures++;
    else if (r.value.error) failures++;
  }

  console.log(
    `[warm] ${reason}: ${Date.now() - startedAt}ms, ${failures} de ${results.length} com falha`,
  );
}
