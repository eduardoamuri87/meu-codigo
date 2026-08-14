import "server-only";
import { currentYearMonth } from "@/lib/format";
import { warmMonthSnapshots } from "@/lib/queries/month-projection";
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

  // Em etapas, e não tudo de uma vez. A Stripe baixa e faz JSON.parse de
  // megabytes; rodando junto com a Iugu num shared-cpu-1x isso satura a CPU,
  // atrasa o event loop e infla o tempo medido da Iugu — foi o que fez o
  // aquecimento estourar 35s quando as páginas levam 11 a 25s. Aqui fora da
  // request, demorar mais em troca de não competir não custa nada.
  //
  // A Iugu vem primeiro porque é a mais lenta e a que alimenta o maior número de
  // chaves derivadas.
  const results: Array<PromiseSettledResult<{ error?: string }>> = [];
  for (const stage of [
    () => [getIuguMonthTotals(year, month)],
    () => [getIuguMonthTotals(next.year, next.month)],
    () => [getStripeMonthTotals(year, month), getStripeMonthTotals(next.year, next.month)],
    () => [
      getStripeBooksMonthTotals(year, month),
      getStripeBooksMonthTotals(next.year, next.month),
    ],
  ]) {
    results.push(...(await Promise.allSettled(stage())));
  }

  // Os getters capturam os próprios erros e devolvem `error` preenchido, então
  // conto as duas formas de falha para o log dizer a verdade.
  let failures = 0;
  for (const r of results) {
    if (r.status === "rejected") failures++;
    else if (r.value.error) failures++;
  }

  // Por último os snapshots dos meses fechados, já com a janela da Iugu quente
  // em memória: sem isso a primeira carga do dashboard pagaria por construí-los.
  let snapshots = { criados: 0, falhas: 0 };
  try {
    snapshots = await warmMonthSnapshots();
  } catch (e) {
    console.error("[warm] snapshots falharam:", e);
  }

  console.log(
    `[warm] ${reason}: ${Date.now() - startedAt}ms, ${failures} de ${results.length} com falha, ` +
      `${snapshots.criados} snapshot(s) criado(s), ${snapshots.falhas} falha(s)`,
  );
}
