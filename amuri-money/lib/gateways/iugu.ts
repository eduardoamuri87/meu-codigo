import "server-only";
import { withTtlCache } from "./memory-cache";
import type { IuguDetailItem } from "./types";

const ONE_HOUR = 60 * 60 * 1000;

const IUGU_BASE = "https://api.iugu.com";

type IuguReturnDate = {
  return_date?: string;
  amount_cents?: number;
  status?: string;
  installment?: number;
  taxes_cents?: number;
  checkout_taxes_cents?: number;
};

type IuguInvoice = {
  paid_at?: string;
  payable_with?: string;
  payer_name?: string;
  customer_name?: string;
  email?: string;
  financial_return_dates?: IuguReturnDate[];
};

type IuguListResponse = {
  totalItems?: number;
  items?: IuguInvoice[];
};

export type IuguMonthResult = {
  recebido: { total: number; items: IuguDetailItem[] };
  aReceber: { total: number; items: IuguDetailItem[] };
};

function authHeader(): string {
  const token = process.env.IUGU_API_TOKEN;
  if (!token) throw new Error("IUGU_API_TOKEN não configurado.");
  return "Basic " + Buffer.from(token + ":").toString("base64");
}

function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

async function fetchAllPaidInvoices(
  paidFrom: string,
  paidTo: string,
): Promise<IuguInvoice[]> {
  const limit = 100;
  const all: IuguInvoice[] = [];
  let start = 0;
  const auth = authHeader();

  while (true) {
    const url = new URL("/v1/invoices", IUGU_BASE);
    url.searchParams.set("limit", String(limit));
    url.searchParams.set("start", String(start));
    url.searchParams.set("status_filter", "paid");
    url.searchParams.set("paid_at_from", paidFrom);
    url.searchParams.set("paid_at_to", paidTo);
    url.searchParams.set("sortBy[paid_at]", "asc");

    const resp = await fetch(url, {
      headers: { Authorization: auth, Accept: "application/json" },
      cache: "no-store",
    });
    if (!resp.ok) {
      throw new Error(`Iugu HTTP ${resp.status}: ${await resp.text()}`);
    }
    const data = (await resp.json()) as IuguListResponse;
    const items = data.items ?? [];
    all.push(...items);
    const total = data.totalItems ?? 0;
    if (all.length >= total || items.length === 0) break;
    start += limit;
  }

  return all;
}

function computeMonth(
  invoices: IuguInvoice[],
  year: number,
  month: number,
): IuguMonthResult {
  const monthPrefix = `${year}-${String(month).padStart(2, "0")}`;
  const today = isoDate(new Date());
  const recebido: IuguDetailItem[] = [];
  const aReceber: IuguDetailItem[] = [];
  let recebidoCents = 0;
  let aReceberCents = 0;

  for (const inv of invoices) {
    const parcels = inv.financial_return_dates ?? [];
    const totalParcelas = parcels.length;
    for (const p of parcels) {
      const rd = p.return_date ?? "";
      if (!rd.startsWith(monthPrefix)) continue;
      const amount = p.amount_cents ?? 0;
      const item: IuguDetailItem = {
        cliente:
          inv.payer_name || inv.customer_name || inv.email || "(sem nome)",
        compraEm: (inv.paid_at ?? "").slice(0, 10),
        liquidaEm: rd,
        parcela: p.installment ?? 0,
        totalParcelas,
        valor: amount / 100,
        metodo: inv.payable_with ?? "",
      };
      const liquidado = p.status === "paid" || rd <= today;
      if (liquidado) {
        recebidoCents += amount;
        recebido.push(item);
      } else {
        aReceberCents += amount;
        aReceber.push(item);
      }
    }
  }

  const byLiquidaAsc = (a: IuguDetailItem, b: IuguDetailItem) =>
    a.liquidaEm.localeCompare(b.liquidaEm);
  recebido.sort(byLiquidaAsc);
  aReceber.sort(byLiquidaAsc);

  return {
    recebido: { total: recebidoCents / 100, items: recebido },
    aReceber: { total: aReceberCents / 100, items: aReceber },
  };
}

function windowKey(): string {
  const now = new Date();
  const from = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 24, 1),
  );
  return isoDate(from);
}

const cachedWindowInvoices = withTtlCache(
  "iugu-invoices-window-v1",
  ONE_HOUR,
  async (fromDate: string): Promise<IuguInvoice[]> => {
    const tomorrow = new Date(Date.now() + 86400 * 1000);
    return fetchAllPaidInvoices(fromDate, isoDate(tomorrow));
  },
);

async function computeIuguMonth(
  year: number,
  month: number,
): Promise<IuguMonthResult> {
  const invoices = await cachedWindowInvoices(windowKey());
  return computeMonth(invoices, year, month);
}

const cachedComputeIuguMonth = withTtlCache(
  "iugu-month-v3",
  ONE_HOUR,
  computeIuguMonth,
);

export type IuguMonthTotals = {
  recebido: { total: number; items: IuguDetailItem[] };
  aReceber: { total: number; items: IuguDetailItem[] };
  error?: string;
};

export type IuguCustomerWithInstallments = {
  cliente: string;
  email: string | null;
  parcelasRestantes: number;
  valorRestante: number;
  proximaLiquidacao: string;
  ultimaLiquidacao: string;
  metodo: string;
};

export async function listIuguCustomersWithInstallments(): Promise<{
  count: number;
  customers: IuguCustomerWithInstallments[];
}> {
  const invoices = await cachedWindowInvoices(windowKey());
  const today = isoDate(new Date());

  const byCustomer = new Map<
    string,
    {
      cliente: string;
      email: string | null;
      metodo: string;
      amountCents: number;
      dates: string[];
    }
  >();

  for (const inv of invoices) {
    const parcels = inv.financial_return_dates ?? [];
    const future = parcels.filter((p) => {
      const rd = p.return_date ?? "";
      if (!rd) return false;
      if (p.status === "paid") return false;
      return rd > today;
    });
    if (future.length === 0) continue;

    const cliente =
      inv.payer_name || inv.customer_name || inv.email || "(sem nome)";
    const email = inv.email ?? null;
    const key = `${cliente}|${email ?? ""}`;
    const entry = byCustomer.get(key) ?? {
      cliente,
      email,
      metodo: inv.payable_with ?? "",
      amountCents: 0,
      dates: [],
    };
    for (const p of future) {
      entry.amountCents += p.amount_cents ?? 0;
      if (p.return_date) entry.dates.push(p.return_date);
    }
    byCustomer.set(key, entry);
  }

  const customers: IuguCustomerWithInstallments[] = [...byCustomer.values()]
    .map((e) => {
      const sorted = e.dates.slice().sort();
      return {
        cliente: e.cliente,
        email: e.email,
        parcelasRestantes: e.dates.length,
        valorRestante: +(e.amountCents / 100).toFixed(2),
        proximaLiquidacao: sorted[0],
        ultimaLiquidacao: sorted[sorted.length - 1],
        metodo: e.metodo,
      };
    })
    .sort((a, b) => a.proximaLiquidacao.localeCompare(b.proximaLiquidacao));

  return { count: customers.length, customers };
}

export async function getIuguMonthTotals(
  year: number,
  month: number,
): Promise<IuguMonthTotals> {
  try {
    return await cachedComputeIuguMonth(year, month);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("[iugu] falhou:", msg);
    return {
      recebido: { total: 0, items: [] },
      aReceber: { total: 0, items: [] },
      error: msg,
    };
  }
}
