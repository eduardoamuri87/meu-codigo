"use server";

import crypto from "node:crypto";
import { revalidatePath, revalidateTag } from "next/cache";
import { eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { costCenters, recurrences, transactions } from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/session";
import { CACHE_TAGS } from "@/lib/queries/page-data";

function invalidateCostCenters() {
  revalidateTag(CACHE_TAGS.costCenters, "max");
  revalidatePath("/centros-de-custo");
}

export type ActionResult = { ok: true } | { ok: false; error: string };

export async function createCostCenter(formData: FormData): Promise<ActionResult> {
  await requireUser();
  const name = String(formData.get("name") ?? "").trim();
  if (!name) return { ok: false, error: "Nome obrigatório." };

  await db.insert(costCenters).values({
    id: crypto.randomUUID(),
    name,
    createdAt: Date.now(),
  });
  invalidateCostCenters();
  return { ok: true };
}

export async function updateCostCenter(formData: FormData): Promise<ActionResult> {
  await requireUser();
  const id = String(formData.get("id") ?? "");
  const name = String(formData.get("name") ?? "").trim();
  if (!id || !name) return { ok: false, error: "Dados inválidos." };

  await db.update(costCenters).set({ name }).where(eq(costCenters.id, id));
  invalidateCostCenters();
  return { ok: true };
}

export async function deleteCostCenter(id: string): Promise<ActionResult> {
  await requireUser();
  if (!id) return { ok: false, error: "Centro de custo inválido." };

  const [ref] = await db
    .select({ id: transactions.id })
    .from(transactions)
    .where(eq(transactions.costCenterId, id))
    .limit(1);
  if (ref) {
    return {
      ok: false,
      error: "Centro de custo em uso em transações — não pode ser excluído.",
    };
  }

  const [refRec] = await db
    .select({ id: recurrences.id })
    .from(recurrences)
    .where(eq(recurrences.costCenterId, id))
    .limit(1);
  if (refRec) {
    return {
      ok: false,
      error: "Centro de custo em uso em recorrências — não pode ser excluído.",
    };
  }

  await db.delete(costCenters).where(eq(costCenters.id, id));
  invalidateCostCenters();
  return { ok: true };
}
