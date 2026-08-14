import "server-only";
import crypto from "node:crypto";
import { revalidateTag } from "next/cache";
import { desc, eq, isNull } from "drizzle-orm";
import { db } from "@/lib/db";
import { recurrences, transactions } from "@/lib/db/schema";
import { CACHE_TAGS } from "@/lib/queries/page-data";

const FOREVER_BATCH = 240;
const EXTEND_WHEN_WITHIN_MONTHS = 24;
const MIN_RUN_INTERVAL_MS = 60 * 60 * 1000;

let lastRunAt = 0;
let inflight: Promise<void> | null = null;

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function computeParcelDate(
  startDate: string,
  parcelIdx: number,
  dayOfMonth: number,
): string {
  if (parcelIdx === 1) return startDate;
  const [y, m] = startDate.split("-").map(Number);
  const totalIdx = y * 12 + (m - 1) + (parcelIdx - 1);
  const ty = Math.floor(totalIdx / 12);
  const tm = (totalIdx % 12) + 1;
  const day = Math.min(dayOfMonth, daysInMonth(ty, tm));
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${ty}-${pad(tm)}-${pad(day)}`;
}

function thresholdDateStr(monthsAhead: number): string {
  const t = new Date();
  const target = new Date(
    Date.UTC(t.getUTCFullYear(), t.getUTCMonth() + monthsAhead, 1),
  );
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${target.getUTCFullYear()}-${pad(target.getUTCMonth() + 1)}-${pad(1)}`;
}

async function runEnsureForeverRecurrences(): Promise<void> {
  const foreverRecs = await db
    .select()
    .from(recurrences)
    .where(isNull(recurrences.totalParcels));
  if (foreverRecs.length === 0) return;

  const threshold = thresholdDateStr(EXTEND_WHEN_WITHIN_MONTHS);
  const now = Date.now();
  let inserted = false;

  await Promise.all(
    foreverRecs.map(async (rec) => {
      const [last] = await db
        .select({
          parcelNumber: transactions.parcelNumber,
          date: transactions.date,
        })
        .from(transactions)
        .where(eq(transactions.recurrenceId, rec.id))
        .orderBy(desc(transactions.parcelNumber))
        .limit(1);
      if (!last || last.parcelNumber === null) return;
      if (last.date >= threshold) return;

      const startParcel = last.parcelNumber + 1;
      const extras = Array.from({ length: FOREVER_BATCH }, (_, i) => ({
        id: crypto.randomUUID(),
        date: computeParcelDate(rec.startDate, startParcel + i, rec.dayOfMonth),
        description: rec.description,
        amount: rec.amount,
        categoryId: rec.categoryId,
        type: rec.type,
        paid: false,
        recurrenceId: rec.id,
        parcelNumber: startParcel + i,
        createdBy: null,
        createdAt: now,
        updatedAt: now,
      }));
      await db.insert(transactions).values(extras);
      inserted = true;
    }),
  );

  // Sem isso as 240 parcelas recém-inseridas ficam invisíveis no unstable_cache
  // até que alguma outra ação invalide a tag.
  if (inserted) {
    try {
      revalidateTag(CACHE_TAGS.transactions, "max");
    } catch (e) {
      console.error("[ensure-forever] revalidateTag falhou:", e);
    }
  }
}

export async function ensureForeverRecurrences(): Promise<void> {
  if (inflight) return inflight;
  if (Date.now() - lastRunAt < MIN_RUN_INTERVAL_MS) return;
  // lastRunAt no finally, não no then: se a rotina falhar (SQLITE_BUSY, por
  // exemplo) ela não pode voltar a rodar em toda request. E o catch fica aqui
  // dentro porque o call site dispara isso sem await — no Node uma rejeição
  // não tratada mata o processo.
  inflight = runEnsureForeverRecurrences()
    .catch((e) => {
      console.error("[ensure-forever] falhou:", e);
    })
    .finally(() => {
      lastRunAt = Date.now();
      inflight = null;
    });
  return inflight;
}
