import { withTtlCache } from "./memory-cache";
import type { StripeBookItem, StripeDetailItem } from "./types";

const STRIPE_BASE = "https://api.stripe.com";
const BANK_DELAY_DAYS = 2;
const DEFAULT_FEE_RATE = 0.045;
const ONE_HOUR = 60 * 60 * 1000;

const BR_HOLIDAYS = new Set<string>([
  // 2026
  "2026-01-01", "2026-02-16", "2026-02-17", "2026-04-03", "2026-04-21",
  "2026-05-01", "2026-06-04", "2026-09-07", "2026-10-12", "2026-11-02",
  "2026-11-15", "2026-11-20", "2026-12-25",
  // 2027
  "2027-01-01", "2027-02-08", "2027-02-09", "2027-03-26", "2027-04-21",
  "2027-05-01", "2027-05-27", "2027-09-07", "2027-10-12", "2027-11-02",
  "2027-11-15", "2027-11-20", "2027-12-25",
  // 2028
  "2028-01-01", "2028-02-28", "2028-02-29", "2028-04-14", "2028-04-21",
  "2028-05-01", "2028-06-15", "2028-09-07", "2028-10-12", "2028-11-02",
  "2028-11-15", "2028-11-20", "2028-12-25",
]);

function isBusinessDayBR(d: Date): boolean {
  const dow = d.getUTCDay();
  if (dow === 0 || dow === 6) return false;
  const iso = d.toISOString().slice(0, 10);
  return !BR_HOLIDAYS.has(iso);
}

function addBusinessDaysBR(unix: number, days: number): number {
  const d = new Date(unix * 1000);
  let remaining = days;
  while (remaining > 0) {
    d.setUTCDate(d.getUTCDate() + 1);
    if (isBusinessDayBR(d)) remaining--;
  }
  return Math.floor(d.getTime() / 1000);
}

type BalanceTransaction = {
  id: string;
  type: string;
  amount: number;
  fee: number;
  net: number;
  available_on: number;
  created: number;
};

type StripeCustomer = {
  id: string;
  name?: string | null;
  email?: string | null;
  description?: string | null;
};

type Price = {
  unit_amount?: number | null;
  recurring?: { interval?: string; interval_count?: number } | null;
  product?: string | { id: string; name?: string } | null;
};

type SubscriptionItem = {
  quantity?: number | null;
  price?: Price | null;
};

type Subscription = {
  id: string;
  status: string;
  created?: number;
  current_period_end?: number;
  cancel_at?: number | null;
  cancel_at_period_end?: boolean;
  customer?: string | StripeCustomer | null;
  items?: { data?: SubscriptionItem[] };
};

type ListResponse<T> = {
  data?: T[];
  has_more?: boolean;
};

type StripeProduct = { id: string; name?: string };

export type StripeMonthTotals = {
  recebido: { total: number; items: StripeDetailItem[] };
  aReceber: { total: number; items: StripeDetailItem[] };
  error?: string;
};

function authHeader(): string {
  const token = process.env.STRIPE_API_TOKEN;
  if (!token) throw new Error("STRIPE_API_TOKEN não configurado.");
  return "Bearer " + token;
}

async function stripeGet<T>(
  path: string,
  qs: Record<string, string | string[]>,
): Promise<T> {
  const url = new URL(path, STRIPE_BASE);
  for (const [k, v] of Object.entries(qs)) {
    if (Array.isArray(v)) {
      for (const vi of v) url.searchParams.append(k, vi);
    } else {
      url.searchParams.set(k, v);
    }
  }
  const resp = await fetch(url, {
    headers: { Authorization: authHeader(), Accept: "application/json" },
    cache: "no-store",
  });
  if (!resp.ok) {
    throw new Error(`Stripe HTTP ${resp.status}: ${await resp.text()}`);
  }
  return (await resp.json()) as T;
}

async function listPaginated<T extends { id: string }>(
  path: string,
  baseQs: Record<string, string | string[]>,
): Promise<T[]> {
  const all: T[] = [];
  let startingAfter: string | null = null;
  while (true) {
    const qs: Record<string, string | string[]> = { ...baseQs, limit: "100" };
    if (startingAfter) qs.starting_after = startingAfter;
    const data = await stripeGet<ListResponse<T>>(path, qs);
    const items = data.data ?? [];
    all.push(...items);
    if (!data.has_more || items.length === 0) break;
    startingAfter = items[items.length - 1].id;
  }
  return all;
}

function monthStartUnix(year: number, month: number): number {
  return Math.floor(Date.UTC(year, month - 1, 1) / 1000);
}

function monthEndUnix(year: number, month: number): number {
  return Math.floor(Date.UTC(year, month, 1) / 1000) - 1;
}

function unixToIso(unix: number): string {
  return new Date(unix * 1000).toISOString().slice(0, 10);
}

async function fetchRecentBalanceTransactions(
  daysBack: number,
): Promise<BalanceTransaction[]> {
  const now = Math.floor(Date.now() / 1000);
  const from = now - daysBack * 86400;
  return listPaginated<BalanceTransaction>("/v1/balance_transactions", {
    "available_on[gte]": String(from),
    "available_on[lte]": String(now),
  });
}

async function fetchActiveSubscriptions(): Promise<Subscription[]> {
  return listPaginated<Subscription>("/v1/subscriptions", {
    status: "active",
    "expand[]": ["data.customer"],
  });
}

async function fetchProductNames(
  subs: Subscription[],
): Promise<Record<string, string>> {
  const ids = new Set<string>();
  for (const s of subs) {
    for (const it of s.items?.data ?? []) {
      const p = it.price?.product;
      if (typeof p === "string") ids.add(p);
    }
  }
  const map: Record<string, string> = {};
  await Promise.all(
    [...ids].map(async (id) => {
      try {
        const prod = await stripeGet<StripeProduct>(`/v1/products/${id}`, {});
        map[id] = prod.name ?? id;
      } catch {
        map[id] = id;
      }
    }),
  );
  return map;
}

function computeEffectiveFeeRate(txs: BalanceTransaction[]): number {
  let gross = 0;
  let fee = 0;
  for (const t of txs) {
    if (t.type !== "charge") continue;
    gross += t.amount;
    fee += t.fee;
  }
  if (gross <= 0) return DEFAULT_FEE_RATE;
  return fee / gross;
}

function subscriptionGrossCents(sub: Subscription): number {
  return (sub.items?.data ?? []).reduce((acc, it) => {
    const unit = it.price?.unit_amount ?? 0;
    const qty = it.quantity ?? 1;
    return acc + unit * qty;
  }, 0);
}

function intervalOf(sub: Subscription): { unit: string; count: number } {
  const r = sub.items?.data?.[0]?.price?.recurring;
  return { unit: r?.interval ?? "month", count: r?.interval_count ?? 1 };
}

function advanceDate(unix: number, unit: string, count: number): number {
  const d = new Date(unix * 1000);
  if (unit === "month") d.setUTCMonth(d.getUTCMonth() + count);
  else if (unit === "year") d.setUTCFullYear(d.getUTCFullYear() + count);
  else if (unit === "week") d.setUTCDate(d.getUTCDate() + 7 * count);
  else d.setUTCDate(d.getUTCDate() + count);
  return Math.floor(d.getTime() / 1000);
}

function customerName(sub: Subscription): string {
  const c = sub.customer;
  if (!c || typeof c !== "object") return "(sem nome)";
  return c.name || c.email || c.description || "(sem nome)";
}

function productName(
  sub: Subscription,
  productMap: Record<string, string>,
): string {
  const p = sub.items?.data?.[0]?.price?.product;
  if (!p) return "";
  if (typeof p === "string") return productMap[p] ?? p;
  return p.name ?? p.id;
}

function remainingCharges(
  sub: Subscription,
  fromChargeUnix: number,
): number | null {
  if (!sub.cancel_at) return null;
  const { unit, count } = intervalOf(sub);
  let t = fromChargeUnix;
  let n = 0;
  while (t <= sub.cancel_at && n < 1000) {
    n++;
    t = advanceDate(t, unit, count);
  }
  return n;
}

function chargeDatesInMonth(
  sub: Subscription,
  year: number,
  month: number,
): number[] {
  const cpe = sub.current_period_end ?? 0;
  if (!cpe) return [];
  const { unit, count } = intervalOf(sub);
  const cancelAt = sub.cancel_at ?? Number.POSITIVE_INFINITY;
  const created = sub.created ?? 0;
  const willRenewCpe = !sub.cancel_at_period_end;
  const mStart = monthStartUnix(year, month);
  const mEnd = monthEndUnix(year, month);
  const delay = BANK_DELAY_DAYS * 86400;
  const out: number[] = [];

  if (willRenewCpe) {
    let t = cpe;
    let guard = 0;
    while (guard < 240) {
      if (t > cancelAt) break;
      if (t + delay > mEnd) break;
      if (t + delay >= mStart) out.push(t);
      t = advanceDate(t, unit, count);
      guard++;
    }
  }

  let t = advanceDate(cpe, unit, -count);
  let guard = 0;
  while (guard < 240) {
    if (t < created) break;
    if (t + delay < mStart) break;
    if (t + delay <= mEnd) out.push(t);
    t = advanceDate(t, unit, -count);
    guard++;
  }

  return out;
}

function computeStripeMonth(
  subs: Subscription[],
  productMap: Record<string, string>,
  feeRate: number,
  year: number,
  month: number,
): StripeMonthTotals {
  const now = Math.floor(Date.now() / 1000);
  const delay = BANK_DELAY_DAYS * 86400;
  const recebido: StripeDetailItem[] = [];
  const aReceber: StripeDetailItem[] = [];
  let recebidoCents = 0;
  let aReceberCents = 0;

  for (const sub of subs) {
    const gross = subscriptionGrossCents(sub);
    if (!gross) continue;
    const netPerChargeCents = Math.round(gross * (1 - feeRate));
    const cliente = customerName(sub);
    const produto = productName(sub, productMap);
    const assinaturaDesde = sub.created ? unixToIso(sub.created) : "";
    const cancelaEm = sub.cancel_at ? unixToIso(sub.cancel_at) : null;

    for (const chargeUnix of chargeDatesInMonth(sub, year, month)) {
      const availableUnix = chargeUnix + delay;
      const item: StripeDetailItem = {
        cliente,
        produto,
        cobrancaEm: unixToIso(chargeUnix),
        disponivelEm: unixToIso(availableUnix),
        valor: netPerChargeCents / 100,
        assinaturaDesde,
        cancelaEm,
        parcelasRestantes: remainingCharges(sub, chargeUnix),
      };
      if (availableUnix < now) {
        recebidoCents += netPerChargeCents;
        recebido.push(item);
      } else {
        aReceberCents += netPerChargeCents;
        aReceber.push(item);
      }
    }
  }

  const byDisponivelAsc = (a: StripeDetailItem, b: StripeDetailItem) =>
    a.disponivelEm.localeCompare(b.disponivelEm);
  recebido.sort(byDisponivelAsc);
  aReceber.sort(byDisponivelAsc);

  return {
    recebido: { total: recebidoCents / 100, items: recebido },
    aReceber: { total: aReceberCents / 100, items: aReceber },
  };
}

const cachedActiveSubs = withTtlCache(
  "stripe-active-subs-v2",
  ONE_HOUR,
  fetchActiveSubscriptions,
);

const cachedProductMap = withTtlCache("stripe-products-v3", ONE_HOUR, async () => {
  const subs = await cachedActiveSubs();
  return fetchProductNames(subs);
});

const cachedFeeRate = withTtlCache("stripe-fee-rate", ONE_HOUR, async () => {
  const txs = await fetchRecentBalanceTransactions(60);
  return computeEffectiveFeeRate(txs);
});

export type StripeSubscriptionSlim = {
  id: string;
  cliente: string;
  produto: string;
  valorMensalBruto: number;
  valorMensalLiquido: number;
  intervalo: { unidade: string; a_cada: number };
  assinaturaDesde: string | null;
  cancelaEm: string | null;
  cancelaNoFimDoPeriodo: boolean;
  parcelasRestantes: number | null;
  proximaCobranca: string | null;
};

export async function listActiveStripeSubscriptions(): Promise<{
  count: number;
  subscriptions: StripeSubscriptionSlim[];
}> {
  try {
    const [subs, productMap, feeRate] = await Promise.all([
      cachedActiveSubs(),
      cachedProductMap(),
      cachedFeeRate(),
    ]);
    const out: StripeSubscriptionSlim[] = subs
      .map((sub) => {
        const gross = subscriptionGrossCents(sub);
        const netCents = Math.round(gross * (1 - feeRate));
        const { unit, count } = intervalOf(sub);
        const nextCharge = sub.current_period_end ?? null;
        return {
          id: sub.id,
          cliente: customerName(sub),
          produto: productName(sub, productMap),
          valorMensalBruto: +(gross / 100).toFixed(2),
          valorMensalLiquido: +(netCents / 100).toFixed(2),
          intervalo: { unidade: unit, a_cada: count },
          assinaturaDesde: sub.created ? unixToIso(sub.created) : null,
          cancelaEm: sub.cancel_at ? unixToIso(sub.cancel_at) : null,
          cancelaNoFimDoPeriodo: !!sub.cancel_at_period_end,
          parcelasRestantes: nextCharge
            ? remainingCharges(sub, nextCharge)
            : null,
          proximaCobranca: nextCharge ? unixToIso(nextCharge) : null,
        };
      })
      .sort((a, b) => a.cliente.localeCompare(b.cliente, "pt-BR"));
    return { count: out.length, subscriptions: out };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("[stripe] list falhou:", msg);
    throw new Error(msg);
  }
}

const BOOK_PRODUCT_NAMES: Record<string, string> = {
  prod_TlI7gCEvvW3wV5: "Dinheiro sem medo — 1 livro",
  prod_TlI4kEHjGA0Sq5: "Dinheiro sem medo — 2 livros",
};

type PaymentIntentExpanded = {
  id: string;
  payment_link?: string | null;
};

type ChargeExpanded = {
  id: string;
  payment_intent?: string | PaymentIntentExpanded | null;
  billing_details?: { name?: string | null; email?: string | null } | null;
};

type BalanceTransactionWithSource = BalanceTransaction & {
  source?: string | ChargeExpanded | null;
};

type CheckoutSessionLineItem = {
  price?: { product?: string | null } | null;
};

type CheckoutSession = {
  id: string;
  status?: string | null;
  mode?: string | null;
  payment_intent?: string | null;
  customer_details?: { name?: string | null; email?: string | null } | null;
  line_items?: { data?: CheckoutSessionLineItem[] } | null;
};

type BookPaymentInfo = { cliente: string; produto: string };

export type StripeBooksMonthTotals = {
  recebido: { total: number; items: StripeBookItem[] };
  aReceber: { total: number; items: StripeBookItem[] };
  error?: string;
};

async function fetchChargeBalanceTransactionsByCreatedWindow(
  year: number,
  month: number,
): Promise<BalanceTransactionWithSource[]> {
  // Listamos charges cujo `created` pode cair dentro do mês visualizado
  // quando somamos 2 dias úteis BR. Pior caso: 2 úteis podem ser até ~7
  // dias de calendário (carnaval, sexta santa + fim de semana). Então um
  // range de [monthStart - 2 dias, monthEnd] cobre charges cujo D+2 útil
  // ainda cai no mês visualizado.
  const rangeStart = monthStartUnix(year, month) - 2 * 86400;
  const rangeEnd = monthEndUnix(year, month);
  const all = await listPaginated<BalanceTransactionWithSource>(
    "/v1/balance_transactions",
    {
      "created[gte]": String(rangeStart),
      "created[lte]": String(rangeEnd),
      "expand[]": ["data.source", "data.source.payment_intent"],
    },
  );
  return all.filter((tx) => tx.type === "charge" || tx.type === "payment");
}

type PaymentLink = { id: string; active?: boolean };
type PaymentLinkLineItem = { price?: { product?: string | null } | null };

async function fetchBookPaymentLinks(): Promise<Record<string, string>> {
  const links = await listPaginated<PaymentLink>("/v1/payment_links", {
    active: "true",
  });
  const result: Record<string, string> = {};
  await Promise.all(
    links.map(async (link) => {
      try {
        const items = await stripeGet<ListResponse<PaymentLinkLineItem>>(
          `/v1/payment_links/${link.id}/line_items`,
          {},
        );
        const matched = (items.data ?? [])
          .map((li) => li.price?.product)
          .find(
            (pid): pid is string =>
              typeof pid === "string" && pid in BOOK_PRODUCT_NAMES,
          );
        if (matched) {
          result[link.id] = BOOK_PRODUCT_NAMES[matched];
        }
      } catch {
        // ignore individual link failure
      }
    }),
  );
  return result;
}

async function fetchBookCheckoutSessions(
  year: number,
  month: number,
): Promise<Record<string, BookPaymentInfo>> {
  const windowStart = monthStartUnix(year, month) - 7 * 86400;
  const windowEnd = monthEndUnix(year, month);
  const sessions = await listPaginated<CheckoutSession>(
    "/v1/checkout/sessions",
    {
      "created[gte]": String(windowStart),
      "created[lte]": String(windowEnd),
      "expand[]": ["data.line_items"],
    },
  );

  const byPI: Record<string, BookPaymentInfo> = {};
  for (const s of sessions) {
    if (s.mode !== "payment") continue;
    if (s.status !== "complete") continue;
    if (!s.payment_intent) continue;
    const items = s.line_items?.data ?? [];
    const matched = items
      .map((li) => li.price?.product)
      .find((pid): pid is string =>
        typeof pid === "string" && pid in BOOK_PRODUCT_NAMES,
      );
    if (!matched) continue;
    const cliente =
      s.customer_details?.name ||
      s.customer_details?.email ||
      "(sem nome)";
    byPI[s.payment_intent] = {
      cliente,
      produto: BOOK_PRODUCT_NAMES[matched],
    };
  }
  return byPI;
}

function computeStripeBooksMonth(
  txs: BalanceTransactionWithSource[],
  bookPIs: Record<string, BookPaymentInfo>,
  bookLinks: Record<string, string>,
  year: number,
  month: number,
): StripeBooksMonthTotals {
  const now = Math.floor(Date.now() / 1000);
  const monthPadded = String(month).padStart(2, "0");
  const monthKey = `${year}-${monthPadded}`;
  const recebido: StripeBookItem[] = [];
  const aReceber: StripeBookItem[] = [];
  let recebidoCents = 0;
  let aReceberCents = 0;

  for (const tx of txs) {
    const source = tx.source;
    if (!source || typeof source !== "object") continue;
    const pi = source.payment_intent;
    const piId = typeof pi === "string" ? pi : pi?.id;
    if (!piId) continue;

    let info: BookPaymentInfo | undefined = bookPIs[piId];
    if (!info && typeof pi === "object" && pi?.payment_link) {
      const produto = bookLinks[pi.payment_link];
      if (produto) {
        const cliente =
          source.billing_details?.name ||
          source.billing_details?.email ||
          "(sem nome)";
        info = { cliente, produto };
      }
    }
    if (!info) continue;

    const disponivelUnix = addBusinessDaysBR(tx.created, BANK_DELAY_DAYS);
    const disponivelIso = unixToIso(disponivelUnix);
    if (disponivelIso.slice(0, 7) !== monthKey) continue;

    const net = tx.net;
    const item: StripeBookItem = {
      cliente: info.cliente,
      produto: info.produto,
      cobrancaEm: unixToIso(tx.created),
      disponivelEm: disponivelIso,
      valor: net / 100,
    };
    if (disponivelUnix <= now) {
      recebidoCents += net;
      recebido.push(item);
    } else {
      aReceberCents += net;
      aReceber.push(item);
    }
  }

  const byDisponivelAsc = (a: StripeBookItem, b: StripeBookItem) =>
    a.disponivelEm.localeCompare(b.disponivelEm);
  recebido.sort(byDisponivelAsc);
  aReceber.sort(byDisponivelAsc);

  return {
    recebido: { total: recebidoCents / 100, items: recebido },
    aReceber: { total: aReceberCents / 100, items: aReceber },
  };
}

const cachedChargeBalanceTransactions = withTtlCache(
  "stripe-charge-btxs-by-created-v1",
  ONE_HOUR,
  fetchChargeBalanceTransactionsByCreatedWindow,
);

const cachedBookCheckoutSessions = withTtlCache(
  "stripe-book-sessions-v1",
  ONE_HOUR,
  fetchBookCheckoutSessions,
);

const cachedBookPaymentLinks = withTtlCache(
  "stripe-book-payment-links-v1",
  ONE_HOUR,
  fetchBookPaymentLinks,
);

export async function getStripeBooksMonthTotals(
  year: number,
  month: number,
): Promise<StripeBooksMonthTotals> {
  try {
    const [txs, bookPIs, bookLinks] = await Promise.all([
      cachedChargeBalanceTransactions(year, month),
      cachedBookCheckoutSessions(year, month),
      cachedBookPaymentLinks(),
    ]);
    return computeStripeBooksMonth(txs, bookPIs, bookLinks, year, month);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("[stripe-books] falhou:", msg);
    return {
      recebido: { total: 0, items: [] },
      aReceber: { total: 0, items: [] },
      error: msg,
    };
  }
}

export async function getStripeMonthTotals(
  year: number,
  month: number,
): Promise<StripeMonthTotals> {
  try {
    const [subs, productMap, feeRate] = await Promise.all([
      cachedActiveSubs(),
      cachedProductMap(),
      cachedFeeRate(),
    ]);
    return computeStripeMonth(subs, productMap, feeRate, year, month);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("[stripe] falhou:", msg);
    return {
      recebido: { total: 0, items: [] },
      aReceber: { total: 0, items: [] },
      error: msg,
    };
  }
}
