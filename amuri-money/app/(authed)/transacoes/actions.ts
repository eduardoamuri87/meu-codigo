"use server";

import crypto from "node:crypto";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { and, eq, gte } from "drizzle-orm";
import { db } from "@/lib/db";
import { recurrences, transactions } from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/session";

export type FormState = { error?: string } | undefined;

type ParsedInput = {
  type: "receita" | "despesa";
  date: string;
  description: string;
  amount: number;
  categoryId: string | null;
  paid: boolean;
};

function parseAmount(s: string): number | null {
  const cleaned = s.trim().replace(/\./g, "").replace(",", ".");
  const n = Number.parseFloat(cleaned);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

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
  const paidRaw = String(formData.get("paid") ?? "false");
  const paid = paidRaw === "true" || paidRaw === "on";

  if (type !== "receita" && type !== "despesa")
    return { ok: false, error: "Tipo inválido." };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date))
    return { ok: false, error: "Data inválida." };
  if (!description) return { ok: false, error: "Descrição obrigatória." };
  const amount = parseAmount(amountStr);
  if (amount === null) return { ok: false, error: "Valor inválido." };

  return {
    ok: true,
    data: { type, date, description, amount, categoryId, paid },
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
  revalidatePath("/");
  redirect("/");
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
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${ty}-${pad(tm)}-${pad(dayOfMonth)}`;
}

async function createRecurrenceImpl(
  userId: string,
  formData: FormData,
): Promise<FormState> {
  const r = readForm(formData);
  if (!r.ok) return { error: r.error };

  const parcelsRaw = Number.parseInt(
    String(formData.get("totalParcels") ?? ""),
    10,
  );
  const dayRaw = Number.parseInt(
    String(formData.get("dayOfMonth") ?? ""),
    10,
  );

  if (!Number.isFinite(parcelsRaw) || parcelsRaw < 2 || parcelsRaw > 240)
    return { error: "Parcelas deve ser entre 2 e 240." };
  if (!Number.isFinite(dayRaw) || dayRaw < 1 || dayRaw > 28)
    return { error: "Dia do mês deve ser entre 1 e 28." };

  const now = Date.now();
  const recurrenceId = crypto.randomUUID();

  await db.insert(recurrences).values({
    id: recurrenceId,
    description: r.data.description,
    amount: r.data.amount,
    categoryId: r.data.categoryId,
    type: r.data.type,
    startDate: r.data.date,
    totalParcels: parcelsRaw,
    dayOfMonth: dayRaw,
    createdAt: now,
  });

  const rows = Array.from({ length: parcelsRaw }, (_, i) => ({
    id: crypto.randomUUID(),
    date: computeParcelDate(r.data.date, i + 1, dayRaw),
    description: r.data.description,
    amount: r.data.amount,
    categoryId: r.data.categoryId,
    type: r.data.type,
    paid: false,
    recurrenceId,
    parcelNumber: i + 1,
    createdBy: userId,
    createdAt: now,
    updatedAt: now,
  }));

  await db.insert(transactions).values(rows);

  revalidatePath("/");
  redirect("/");
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
  revalidatePath("/");
  redirect("/");
}

export async function toggleTransactionPaid(id: string, paid: boolean) {
  await requireUser();
  await db
    .update(transactions)
    .set({ paid, updatedAt: Date.now() })
    .where(eq(transactions.id, id));
  revalidatePath("/");
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
      revalidatePath("/");
      return;
    }
  }

  await db.delete(transactions).where(eq(transactions.id, id));
  revalidatePath("/");
}
