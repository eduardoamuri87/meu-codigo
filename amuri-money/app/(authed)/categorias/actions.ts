"use server";

import crypto from "node:crypto";
import { revalidatePath, revalidateTag } from "next/cache";
import { eq } from "drizzle-orm";
import { db } from "@/lib/db";
import {
  categories,
  recurrences,
  transactions,
} from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/session";
import { CACHE_TAGS } from "@/lib/queries/page-data";

function invalidateCategories() {
  revalidateTag(CACHE_TAGS.categories, "max");
  revalidatePath("/categorias");
}

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
  invalidateCategories();
  return { ok: true };
}

export async function createCategoryInline(
  name: string,
  type: string,
): Promise<{ id: string; name: string; type: CategoryType }> {
  await requireUser();
  const validType = validate(name, type);
  if (!validType) throw new Error("Nome ou tipo inválidos.");
  const trimmed = name.trim();

  const id = crypto.randomUUID();
  await db.insert(categories).values({
    id,
    name: trimmed,
    type: validType,
    createdAt: Date.now(),
  });
  invalidateCategories();
  return { id, name: trimmed, type: validType };
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
  invalidateCategories();
  revalidateTag(CACHE_TAGS.transactions, "max");
  revalidatePath("/");
  return { ok: true };
}

export async function deleteCategory(id: string): Promise<ActionResult> {
  await requireUser();
  if (!id) return { ok: false, error: "Categoria inválida." };

  await db.transaction(async (tx) => {
    await tx
      .update(transactions)
      .set({ categoryId: null, updatedAt: Date.now() })
      .where(eq(transactions.categoryId, id));
    await tx
      .update(recurrences)
      .set({ categoryId: null })
      .where(eq(recurrences.categoryId, id));
    await tx.delete(categories).where(eq(categories.id, id));
  });

  invalidateCategories();
  revalidateTag(CACHE_TAGS.transactions, "max");
  revalidatePath("/");
  return { ok: true };
}
