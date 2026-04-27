import crypto from "node:crypto";
import { and, eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { categories, transactions, users } from "@/lib/db/schema";

type Row = {
  date: string;
  description: string;
  amount: number;
  categoryName: string | null;
  paid: boolean;
};

const ROWS: Row[] = [
  { date: "2026-04-10", description: "Clubeco", amount: 2800.0, categoryName: "Aluguel", paid: true },
  { date: "2026-04-13", description: "Cartão Nu", amount: 1928.97, categoryName: null, paid: true },
  { date: "2026-04-15", description: "Plano de saúde - Rita - Amil", amount: 2537.02, categoryName: "Saúde", paid: true },
  { date: "2026-04-16", description: "Conta Conjunta", amount: 2000.0, categoryName: null, paid: true },
  { date: "2026-04-17", description: "DAS", amount: 6188.04, categoryName: "DAS", paid: true },
  { date: "2026-04-17", description: "DARF", amount: 178.31, categoryName: "DARF", paid: true },
  { date: "2026-04-29", description: "Helô", amount: 2305.0, categoryName: "Salário", paid: false },
  { date: "2026-04-29", description: "Camila", amount: 7158.03, categoryName: "Bônus", paid: false },
  { date: "2026-04-29", description: "Helô", amount: 1724.41, categoryName: "Bônus", paid: false },
  { date: "2026-04-29", description: "Cartão", amount: 18927.32, categoryName: "Cartão", paid: false },
  { date: "2026-04-30", description: "Camila", amount: 5760.0, categoryName: "Salário", paid: false },
  { date: "2026-04-30", description: "Camila - Adicional", amount: 5000.0, categoryName: "Salário", paid: false },
];

async function ensureCategory(name: string): Promise<string> {
  const [existing] = await db
    .select({ id: categories.id })
    .from(categories)
    .where(and(eq(categories.name, name), eq(categories.type, "despesa")))
    .limit(1);
  if (existing) return existing.id;
  const id = crypto.randomUUID();
  await db.insert(categories).values({
    id,
    name,
    type: "despesa",
    createdAt: Date.now(),
  });
  console.log(`categoria criada: ${name}`);
  return id;
}

async function main() {
  const [eduardo] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, "eduardo@amuri.com.br"))
    .limit(1);
  if (!eduardo) throw new Error("usuário eduardo@amuri.com.br não encontrado");

  const uniqueCats = [
    ...new Set(ROWS.map((r) => r.categoryName).filter((x): x is string => !!x)),
  ];
  const catMap = new Map<string, string>();
  for (const name of uniqueCats) catMap.set(name, await ensureCategory(name));

  const now = Date.now();
  for (const r of ROWS) {
    await db.insert(transactions).values({
      id: crypto.randomUUID(),
      date: r.date,
      description: r.description,
      amount: r.amount,
      categoryId: r.categoryName ? catMap.get(r.categoryName) ?? null : null,
      type: "despesa",
      paid: r.paid,
      createdBy: eduardo.id,
      createdAt: now,
      updatedAt: now,
    });
    console.log(
      `+ ${r.date} ${r.description} R$ ${r.amount.toFixed(2)}${r.paid ? " [pago]" : ""}`,
    );
  }
  console.log(`\ntotal: ${ROWS.length} despesas inseridas`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
