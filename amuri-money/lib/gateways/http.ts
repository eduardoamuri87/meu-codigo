import "server-only";

/**
 * Camada HTTP dos gateways.
 *
 * O `fetch` do Node não tem timeout default: sem AbortSignal, um socket
 * pendurado da Iugu ou da Stripe trava o render da página indefinidamente e
 * segura memória. E como as duas APIs são paginadas em laços sequenciais, um
 * timeout por request não basta — precisa de um orçamento para a operação
 * inteira, senão 50 páginas de 10s viram 500s.
 */

/**
 * Timeout de uma request isolada.
 *
 * Medido em produção: /v1/invoices da Iugu leva 15 a 25s por página, e isso é
 * custo fixo da API — não muda tirando `sortBy`, nem `status_filter`, nem
 * reduzindo a janela (67 faturas ainda levaram 15s). Um teto de 10s aqui não
 * protegia nada: só garantia que a Iugu nunca respondesse.
 */
export const REQUEST_TIMEOUT_MS = 35_000;

/**
 * Orçamento de uma operação inteira, incluindo todas as páginas.
 *
 * A janela de 24 meses da Iugu são 4 páginas; em paralelo isso fica na casa dos
 * 30 a 50s. Medido também: /v1/checkout/sessions da Stripe chegou a 10 páginas /
 * 21s. O teto existe para impedir que uma API pendurada trave o render para
 * sempre, não para cortar trabalho legítimo.
 */
export const OPERATION_BUDGET_MS = 120_000;

/** Teto de páginas por operação, para que um cursor bugado não rode para sempre. */
export const MAX_PAGES = 50;

export class Deadline {
  private readonly at: number;

  constructor(budgetMs: number = OPERATION_BUDGET_MS) {
    this.at = Date.now() + budgetMs;
  }

  remainingMs(): number {
    return this.at - Date.now();
  }

  expired(): boolean {
    return this.remainingMs() <= 0;
  }
}

export async function fetchJson<T>(
  label: string,
  url: URL,
  headers: Record<string, string>,
  deadline?: Deadline,
): Promise<T> {
  const budget = deadline?.remainingMs() ?? REQUEST_TIMEOUT_MS;
  if (budget <= 0) {
    throw new Error(`${label}: orçamento de tempo esgotado.`);
  }

  let resp: Response;
  try {
    resp = await fetch(url, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(Math.min(REQUEST_TIMEOUT_MS, budget)),
    });
  } catch (e) {
    if (e instanceof Error && e.name === "TimeoutError") {
      throw new Error(`${label}: não respondeu em ${REQUEST_TIMEOUT_MS / 1000}s.`);
    }
    throw e;
  }

  if (!resp.ok) {
    throw new Error(`${label} HTTP ${resp.status}: ${await resp.text()}`);
  }
  return (await resp.json()) as T;
}
