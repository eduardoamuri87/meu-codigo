import "server-only";
import crypto from "node:crypto";
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { categories } from "@/lib/db/schema";

export const GATEWAY_CATEGORIES = [
  { name: "Recebimentos Iugu", type: "receita" as const },
  { name: "Recebimentos Stripe", type: "receita" as const },
  { name: "Recebimentos Livros", type: "receita" as const },
];

let done = false;
let inflight: Promise<void> | null = null;

async function run(): Promise<void> {
  await Promise.all(
    GATEWAY_CATEGORIES.map(async (c) => {
      const [existing] = await db
        .select({ id: categories.id })
        .from(categories)
        .where(and(eq(categories.name, c.name), eq(categories.type, c.type)))
        .limit(1);
      if (existing) return;
      await db.insert(categories).values({
        id: crypto.randomUUID(),
        name: c.name,
        type: c.type,
        createdAt: Date.now(),
      });
    }),
  );
}

export async function ensureGatewayCategories(): Promise<void> {
  if (done) return;
  if (inflight) return inflight;
  inflight = run()
    .then(() => {
      done = true;
    })
    .finally(() => {
      inflight = null;
    });
  return inflight;
}
