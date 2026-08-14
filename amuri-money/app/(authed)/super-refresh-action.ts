"use server";

import { revalidatePath, revalidateTag } from "next/cache";
import { requireUser } from "@/lib/auth/session";
import { clearGatewayCache } from "@/lib/gateways/memory-cache";
import { CACHE_TAGS } from "@/lib/queries/page-data";
import { clearMonthSnapshots } from "@/lib/queries/month-projection";

export async function superRefreshAction() {
  await requireUser();
  await clearGatewayCache();
  // "Atualizar tudo" também descarta os snapshots de meses fechados, senão o
  // saldo inicial continuaria vindo de valores congelados.
  await clearMonthSnapshots();
  revalidateTag(CACHE_TAGS.transactions, "max");
  revalidateTag(CACHE_TAGS.categories, "max");
  revalidateTag(CACHE_TAGS.costCenters, "max");
  revalidatePath("/", "layout");
}
