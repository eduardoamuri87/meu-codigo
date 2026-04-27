"use server";

import { revalidatePath, revalidateTag } from "next/cache";
import { requireUser } from "@/lib/auth/session";
import { clearGatewayCache } from "@/lib/gateways/memory-cache";
import { CACHE_TAGS } from "@/lib/queries/page-data";

export async function superRefreshAction() {
  await requireUser();
  await clearGatewayCache();
  revalidateTag(CACHE_TAGS.transactions, "max");
  revalidateTag(CACHE_TAGS.categories, "max");
  revalidateTag(CACHE_TAGS.costCenters, "max");
  revalidatePath("/", "layout");
}
