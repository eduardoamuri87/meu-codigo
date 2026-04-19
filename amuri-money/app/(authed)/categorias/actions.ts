"use server";

import crypto from "node:crypto";
import { revalidatePath } from "next/cache";
import { eq } from "drizzle-orm";
import { db } from "@/lib/db";
import {
  categories,
  recurrences,
  transactions,
} from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/session";

export type CategoryType = "receita" | "despesa";

export type ActionResult = { ok: true } | { ok: false; error: string };

function validate(name: string, type: string): CategoryType | null {
  if (!name.trim()) return null;
  if (type !== "receita" && type !== "despesa") return null;
  return type;
}

export async function createCategory(formData: FormData): Promise<ActionResult> {
  await requireUser();
  const name = String(formData.get("name") ?? "").trim();
  const rawType = String(formData.get("type") ?? "");
  const type = validate(name, rawType);
  if (!type) return { ok: false, error: "Preencha nome e tipo." };

  await db.insert(categories).values({
    id: crypto.randomUUID(),
    name,
    type,
    createdAt: Date.now(),
  });
  revalidatePath("/categorias");
  return { ok: true };
}

export async function updateCategory(formData: FormData): Promise<ActionResult> {
  await requireUser();
  const id = String(formData.get("id") ?? "");
  const name = String(formData.get("name") ?? "").trim();
  const rawType = String(formData.get("type") ?? "");
  const type = validate(name, rawType);
  if (!id || !type) return { ok: false, error: "Dados inválidos." };

  await db
    .update(categories)
    .set({ name, type })
    .where(eq(categories.id, id));
  revalidatePath("/categorias");
  return { ok: true };
}

export async function deleteCategory(id: string): Promise<ActionResult> {
  await requireUser();
  if (!id) return { ok: false, error: "Categoria inválida." };

  const [ref] = await db
    .select({ id: transactions.id })
    .from(transactions)
    .where(eq(transactions.categoryId, id))
    .limit(1);
  if (ref) {
    return {
      ok: false,
      error: "Categoria em uso em transações — não pode ser excluída.",
    };
  }

  const [refRec] = await db
    .select({ id: recurrences.id })
    .from(recurrences)
    .where(eq(recurrences.categoryId, id))
    .limit(1);
  if (refRec) {
    return {
      ok: false,
      error: "Categoria em uso em recorrências — não pode ser excluída.",
    };
  }

  await db.delete(categories).where(eq(categories.id, id));
  revalidatePath("/categorias");
  return { ok: true };
}
