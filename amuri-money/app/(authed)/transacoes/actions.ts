"use server";

import crypto from "node:crypto";
import { revalidatePath, revalidateTag } from "next/cache";
import { and, eq, gt, gte, ne } from "drizzle-orm";
import { db } from "@/lib/db";
import { recurrences, transactions } from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/session";
import { parseDecimalBR } from "@/lib/format";
import { CACHE_TAGS } from "@/lib/queries/page-data";

function invalidateTransactions() {
  revalidateTag(CACHE_TAGS.transactions, "max");
  revalidatePath("/");
}

export type FormState = { error?: string; ok?: boolean } | undefined;

type ParsedInput = {
  type: "receita" | "despesa";
  date: string;
  description: string;
  amount: number;
  categoryId: string | null;
  costCenterId: string | null;
  paid: boolean;
};

const parseAmount = parseDecimalBR;

function readForm(formData: FormData):
  | { ok: true; data: ParsedInput }
  | { ok: false; error: string } {
  const type = String(formData.get("type") ?? "");
  const date = String(formData.get("date") ?? "");
  const description = String(formData.get("description") ?? "").trim();
  const amountStr = String(formData.get("amount") ?? "");
  const categoryRaw = formData.get("categoryId");
  const categoryStr = categoryRaw ? String(categoryRaw) : "";
  const categoryId =
    categoryStr && categoryStr !== "__none__" ? categoryStr : null;
  const costCenterRaw = formData.get("costCenterId");
  const costCenterStr = costCenterRaw ? String(costCenterRaw) : "";
  const costCenterIdRaw =
    costCenterStr && costCenterStr !== "__none__" ? costCenterStr : null;
  const paidRaw = String(formData.get("paid") ?? "false");
  const paid = paidRaw === "true" || paidRaw === "on";

  if (type !== "receita" && type !== "despesa")
    return { ok: false, error: "Tipo inválido." };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date))
    return { ok: false, error: "Data inválida." };
  if (!description) return { ok: false, error: "Descrição obrigatória." };
  const amount = parseAmount(amountStr);
  if (amount === null) return { ok: false, error: "Valor inválido." };

  const costCenterId = type === "despesa" ? costCenterIdRaw : null;

  return {
    ok: true,
    data: { type, date, description, amount, categoryId, costCenterId, paid },
  };
}

export async function createTransaction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const user = await requireUser();
  if (formData.get("isRecurrent") === "true") {
    return createRecurrenceImpl(user.id, formData);
  }

  const r = readForm(formData);
  if (!r.ok) return { error: r.error };

  const now = Date.now();
  await db.insert(transactions).values({
    id: crypto.randomUUID(),
    ...r.data,
    createdBy: user.id,
    createdAt: now,
    updatedAt: now,
  });
  invalidateTransactions();
  return { ok: true };
}

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

const FOREVER_BATCH = 240;

async function createRecurrenceImpl(
  userId: string,
  formData: FormData,
): Promise<FormState> {
  const r = readForm(formData);
  if (!r.ok) return { error: r.error };

  const forever = formData.get("foreverRecurrence") === "true";
  const dayRaw = Number.parseInt(
    String(formData.get("dayOfMonth") ?? ""),
    10,
  );

  let parcelsToGenerate: number;
  let totalParcels: number | null;
  if (forever) {
    parcelsToGenerate = FOREVER_BATCH;
    totalParcels = null;
  } else {
    const parcelsRaw = Number.parseInt(
      String(formData.get("totalParcels") ?? ""),
      10,
    );
    if (!Number.isFinite(parcelsRaw) || parcelsRaw < 2 || parcelsRaw > 240)
      return { error: "Parcelas deve ser entre 2 e 240." };
    parcelsToGenerate = parcelsRaw;
    totalParcels = parcelsRaw;
  }

  if (!Number.isFinite(dayRaw) || dayRaw < 1 || dayRaw > 31)
    return { error: "Dia do mês deve ser entre 1 e 31." };

  const now = Date.now();
  const recurrenceId = crypto.randomUUID();

  await db.insert(recurrences).values({
    id: recurrenceId,
    description: r.data.description,
    amount: r.data.amount,
    categoryId: r.data.categoryId,
    costCenterId: r.data.costCenterId,
    type: r.data.type,
    startDate: r.data.date,
    totalParcels,
    dayOfMonth: dayRaw,
    createdAt: now,
  });

  const rows = Array.from({ length: parcelsToGenerate }, (_, i) => ({
    id: crypto.randomUUID(),
    date: computeParcelDate(r.data.date, i + 1, dayRaw),
    description: r.data.description,
    amount: r.data.amount,
    categoryId: r.data.categoryId,
    costCenterId: r.data.costCenterId,
    type: r.data.type,
    paid: false,
    recurrenceId,
    parcelNumber: i + 1,
    createdBy: userId,
    createdAt: now,
    updatedAt: now,
  }));

  await db.insert(transactions).values(rows);

  invalidateTransactions();
  return { ok: true };
}

export async function updateTransaction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  await requireUser();
  const id = String(formData.get("id") ?? "");
  if (!id) return { error: "ID inválido." };

  const r = readForm(formData);
  if (!r.ok) return { error: r.error };

  await db
    .update(transactions)
    .set({ ...r.data, updatedAt: Date.now() })
    .where(eq(transactions.id, id));
  invalidateTransactions();
  return { ok: true };
}

export async function convertToRecurrent(
  id: string,
  totalParcelsOrForever: number | "forever",
  dayOfMonth: number,
): Promise<void> {
  const user = await requireUser();
  if (!id) throw new Error("ID inválido.");
  const forever = totalParcelsOrForever === "forever";
  if (!forever) {
    if (
      !Number.isFinite(totalParcelsOrForever) ||
      (totalParcelsOrForever as number) < 2 ||
      (totalParcelsOrForever as number) > 240
    )
      throw new Error("Parcelas deve ser entre 2 e 240.");
  }
  if (!Number.isFinite(dayOfMonth) || dayOfMonth < 1 || dayOfMonth > 31)
    throw new Error("Dia do mês deve ser entre 1 e 31.");

  const [tx] = await db
    .select()
    .from(transactions)
    .where(eq(transactions.id, id))
    .limit(1);
  if (!tx) throw new Error("Transação não encontrada.");
  if (tx.recurrenceId)
    throw new Error("Transação já pertence a uma recorrência.");

  const now = Date.now();
  const recurrenceId = crypto.randomUUID();
  const parcelsToGenerate = forever
    ? FOREVER_BATCH
    : (totalParcelsOrForever as number);

  await db.insert(recurrences).values({
    id: recurrenceId,
    description: tx.description,
    amount: tx.amount,
    categoryId: tx.categoryId,
    costCenterId: tx.costCenterId,
    type: tx.type,
    startDate: tx.date,
    totalParcels: forever ? null : (totalParcelsOrForever as number),
    dayOfMonth,
    createdAt: now,
  });

  await db
    .update(transactions)
    .set({ recurrenceId, parcelNumber: 1, updatedAt: now })
    .where(eq(transactions.id, id));

  const extras = Array.from({ length: parcelsToGenerate - 1 }, (_, i) => ({
    id: crypto.randomUUID(),
    date: computeParcelDate(tx.date, i + 2, dayOfMonth),
    description: tx.description,
    amount: tx.amount,
    categoryId: tx.categoryId,
    costCenterId: tx.costCenterId,
    type: tx.type,
    paid: false,
    recurrenceId,
    parcelNumber: i + 2,
    createdBy: user.id,
    createdAt: now,
    updatedAt: now,
  }));

  if (extras.length > 0) await db.insert(transactions).values(extras);

  invalidateTransactions();
}

export type EditableField = "date" | "description" | "categoryId" | "amount";

export async function updateTransactionField(
  id: string,
  field: EditableField,
  rawValue: string,
): Promise<void> {
  await requireUser();
  if (!id) throw new Error("ID inválido.");

  const updates: Partial<{
    date: string;
    description: string;
    categoryId: string | null;
    amount: number;
  }> = {};

  switch (field) {
    case "date": {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(rawValue)) throw new Error("Data inválida.");
      updates.date = rawValue;
      break;
    }
    case "description": {
      const v = rawValue.trim();
      if (!v) throw new Error("Descrição obrigatória.");
      updates.description = v;
      break;
    }
    case "amount": {
      const n = parseAmount(rawValue);
      if (n === null) throw new Error("Valor inválido.");
      updates.amount = n;
      break;
    }
    case "categoryId": {
      updates.categoryId =
        !rawValue || rawValue === "__none__" ? null : rawValue;
      break;
    }
  }

  await db
    .update(transactions)
    .set({ ...updates, updatedAt: Date.now() })
    .where(eq(transactions.id, id));
  invalidateTransactions();
}

export async function toggleTransactionPaid(id: string, paid: boolean) {
  await requireUser();
  await db
    .update(transactions)
    .set({ paid, updatedAt: Date.now() })
    .where(eq(transactions.id, id));
  invalidateTransactions();
}

export type DeleteScope = "single" | "futures";

export async function deleteTransaction(
  id: string,
  scope: DeleteScope = "single",
) {
  await requireUser();

  if (scope === "futures") {
    const [tx] = await db
      .select({
        recurrenceId: transactions.recurrenceId,
        date: transactions.date,
      })
      .from(transactions)
      .where(eq(transactions.id, id))
      .limit(1);

    if (tx?.recurrenceId) {
      await db
        .delete(transactions)
        .where(
          and(
            eq(transactions.recurrenceId, tx.recurrenceId),
            gte(transactions.date, tx.date),
            eq(transactions.paid, false),
          ),
        );
      invalidateTransactions();
      return;
    }
  }

  await db.delete(transactions).where(eq(transactions.id, id));
  invalidateTransactions();
}

export async function unlinkRecurrence(transactionId: string): Promise<void> {
  await requireUser();
  if (!transactionId) throw new Error("Transação inválida.");

  const [tx] = await db
    .select({ recurrenceId: transactions.recurrenceId })
    .from(transactions)
    .where(eq(transactions.id, transactionId))
    .limit(1);
  if (!tx?.recurrenceId)
    throw new Error("Transação não faz parte de uma recorrência.");

  await db
    .update(transactions)
    .set({ recurrenceId: null, parcelNumber: null, updatedAt: Date.now() })
    .where(eq(transactions.recurrenceId, tx.recurrenceId));

  await db.delete(recurrences).where(eq(recurrences.id, tx.recurrenceId));
  invalidateTransactions();
}

export type RecurrentEditScope = "single" | "futures" | "all";

export type RecurrentEditPatch = {
  description?: string;
  amount?: number;
  categoryId?: string | null;
  costCenterId?: string | null;
  dayOfMonth?: number;
};

export async function updateRecurrentTransaction(
  transactionId: string,
  scope: RecurrentEditScope,
  patch: RecurrentEditPatch,
): Promise<void> {
  await requireUser();
  if (!transactionId) throw new Error("Transação inválida.");

  const [tx] = await db
    .select()
    .from(transactions)
    .where(eq(transactions.id, transactionId))
    .limit(1);
  if (!tx) throw new Error("Transação não encontrada.");

  if (patch.description !== undefined && !patch.description.trim())
    throw new Error("Descrição obrigatória.");
  if (patch.amount !== undefined && (!Number.isFinite(patch.amount) || patch.amount < 0))
    throw new Error("Valor inválido.");
  if (
    patch.dayOfMonth !== undefined &&
    (!Number.isFinite(patch.dayOfMonth) ||
      patch.dayOfMonth < 1 ||
      patch.dayOfMonth > 31)
  )
    throw new Error("Dia do mês deve ser entre 1 e 31.");

  const now = Date.now();

  if (scope === "single") {
    const cols: Record<string, unknown> = {};
    if (patch.description !== undefined) cols.description = patch.description.trim();
    if (patch.amount !== undefined) cols.amount = patch.amount;
    if (patch.categoryId !== undefined) cols.categoryId = patch.categoryId;
    if (patch.costCenterId !== undefined) cols.costCenterId = patch.costCenterId;
    if (Object.keys(cols).length === 0) return;
    await db
      .update(transactions)
      .set({ ...cols, updatedAt: now })
      .where(eq(transactions.id, transactionId));
    invalidateTransactions();
    return;
  }

  if (!tx.recurrenceId)
    throw new Error("Transação não faz parte de uma recorrência.");

  const [rec] = await db
    .select()
    .from(recurrences)
    .where(eq(recurrences.id, tx.recurrenceId))
    .limit(1);
  if (!rec) throw new Error("Recorrência não encontrada.");

  const recCols: Record<string, unknown> = {};
  if (patch.description !== undefined) recCols.description = patch.description.trim();
  if (patch.amount !== undefined) recCols.amount = patch.amount;
  if (patch.categoryId !== undefined) recCols.categoryId = patch.categoryId;
  if (patch.costCenterId !== undefined) recCols.costCenterId = patch.costCenterId;
  if (patch.dayOfMonth !== undefined) recCols.dayOfMonth = patch.dayOfMonth;
  if (Object.keys(recCols).length > 0) {
    await db.update(recurrences).set(recCols).where(eq(recurrences.id, tx.recurrenceId));
  }

  const txCols: Record<string, unknown> = {};
  if (patch.description !== undefined) txCols.description = patch.description.trim();
  if (patch.amount !== undefined) txCols.amount = patch.amount;
  if (patch.categoryId !== undefined) txCols.categoryId = patch.categoryId;
  if (patch.costCenterId !== undefined) txCols.costCenterId = patch.costCenterId;

  // A parcela atual é sempre atualizada, mesmo se já estiver paid=true.
  // As demais (cascata por scope) respeitam paid=false pra não mexer em
  // histórico já liquidado.
  if (Object.keys(txCols).length > 0 || patch.dayOfMonth !== undefined) {
    const atualSet: Record<string, unknown> = { ...txCols, updatedAt: now };
    if (patch.dayOfMonth !== undefined) {
      atualSet.date = computeParcelDate(
        rec.startDate,
        tx.parcelNumber ?? 1,
        patch.dayOfMonth,
      );
    }
    await db
      .update(transactions)
      .set(atualSet)
      .where(eq(transactions.id, transactionId));
  }

  const demaisFilter = and(
    eq(transactions.recurrenceId, tx.recurrenceId),
    eq(transactions.paid, false),
    ne(transactions.id, transactionId),
    scope === "futures"
      ? gt(transactions.parcelNumber, tx.parcelNumber ?? 0)
      : gte(transactions.parcelNumber, 1),
  );

  if (patch.dayOfMonth !== undefined) {
    const rows = await db
      .select({ id: transactions.id, parcelNumber: transactions.parcelNumber })
      .from(transactions)
      .where(demaisFilter);

    for (const row of rows) {
      const newDate = computeParcelDate(
        rec.startDate,
        row.parcelNumber ?? 1,
        patch.dayOfMonth,
      );
      await db
        .update(transactions)
        .set({ ...txCols, date: newDate, updatedAt: now })
        .where(eq(transactions.id, row.id));
    }
  } else if (Object.keys(txCols).length > 0) {
    await db
      .update(transactions)
      .set({ ...txCols, updatedAt: now })
      .where(demaisFilter);
  }

  invalidateTransactions();
}
