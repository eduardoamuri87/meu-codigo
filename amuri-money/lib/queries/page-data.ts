import "server-only";
import { unstable_cache } from "next/cache";
import { and, asc, desc, eq, gte, like, lt, sql } from "drizzle-orm";
import { db } from "@/lib/db";
import {
  categories,
  costCenters,
  recurrences,
  transactions,
} from "@/lib/db/schema";
import { monthRange } from "@/lib/format";

export const CACHE_TAGS = {
  transactions: "transactions",
  categories: "categories",
  costCenters: "cost-centers",
} as const;

export type TypeFilter = "todos" | "receita" | "despesa";

export type DbRow = {
  id: string;
  date: string;
  description: string;
  amount: number;
  type: "receita" | "despesa";
  paid: boolean;
  categoryId: string | null;
  categoryName: string | null;
  costCenterId: string | null;
  costCenterName: string | null;
  recurrenceId: string | null;
  parcelNumber: number | null;
  totalParcels: number | null;
  dayOfMonth: number | null;
};

export const getCachedCategories = unstable_cache(
  async () => db.select().from(categories).orderBy(asc(categories.name)),
  ["page-categories-v1"],
  { tags: [CACHE_TAGS.categories] },
);

export const getCachedCostCenters = unstable_cache(
  async () => db.select().from(costCenters).orderBy(asc(costCenters.name)),
  ["page-cost-centers-v1"],
  { tags: [CACHE_TAGS.costCenters] },
);

type MonthTotals = {
  recebido: number;
  aReceber: number;
  pago: number;
  aPagar: number;
};

export const getCachedMonthTotals = unstable_cache(
  async (year: number, month: number): Promise<MonthTotals> => {
    const { start, end } = monthRange(year, month);
    const [row] = await db
      .select({
        recebido: sql<number>`COALESCE(SUM(CASE WHEN ${transactions.type} = 'receita' AND ${transactions.paid} = 1 THEN ${transactions.amount} ELSE 0 END), 0)`,
        aReceber: sql<number>`COALESCE(SUM(CASE WHEN ${transactions.type} = 'receita' AND ${transactions.paid} = 0 THEN ${transactions.amount} ELSE 0 END), 0)`,
        pago: sql<number>`COALESCE(SUM(CASE WHEN ${transactions.type} = 'despesa' AND ${transactions.paid} = 1 THEN ${transactions.amount} ELSE 0 END), 0)`,
        aPagar: sql<number>`COALESCE(SUM(CASE WHEN ${transactions.type} = 'despesa' AND ${transactions.paid} = 0 THEN ${transactions.amount} ELSE 0 END), 0)`,
      })
      .from(transactions)
      .where(and(gte(transactions.date, start), lt(transactions.date, end)));
    return {
      recebido: row?.recebido ?? 0,
      aReceber: row?.aReceber ?? 0,
      pago: row?.pago ?? 0,
      aPagar: row?.aPagar ?? 0,
    };
  },
  ["page-month-totals-v1"],
  { tags: [CACHE_TAGS.transactions] },
);

export const getCachedMonthRows = unstable_cache(
  async (
    year: number,
    month: number,
    tipo: TypeFilter,
    q: string,
  ): Promise<DbRow[]> => {
    const { start, end } = monthRange(year, month);
    const trimmed = q.trim();
    const monthWhere = and(
      gte(transactions.date, start),
      lt(transactions.date, end),
    );
    const listWhere = and(
      trimmed ? undefined : monthWhere,
      tipo === "todos" ? undefined : eq(transactions.type, tipo),
      trimmed
        ? like(
            sql`LOWER(${transactions.description})`,
            `%${trimmed.toLowerCase()}%`,
          )
        : undefined,
    );

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
        costCenterId: transactions.costCenterId,
        costCenterName: costCenters.name,
        recurrenceId: transactions.recurrenceId,
        parcelNumber: transactions.parcelNumber,
        totalParcels: recurrences.totalParcels,
        dayOfMonth: recurrences.dayOfMonth,
      })
      .from(transactions)
      .leftJoin(categories, eq(transactions.categoryId, categories.id))
      .leftJoin(costCenters, eq(transactions.costCenterId, costCenters.id))
      .leftJoin(recurrences, eq(transactions.recurrenceId, recurrences.id))
      .where(listWhere)
      .orderBy(desc(transactions.date), asc(transactions.description));

    return rows as DbRow[];
  },
  ["page-month-rows-v1"],
  { tags: [CACHE_TAGS.transactions] },
);
