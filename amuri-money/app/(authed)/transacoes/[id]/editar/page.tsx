import { notFound } from "next/navigation";
import { asc, eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { categories, transactions } from "@/lib/db/schema";
import { TransactionForm } from "../../transaction-form";

export default async function EditarTransacaoPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  const [tx] = await db
    .select()
    .from(transactions)
    .where(eq(transactions.id, id))
    .limit(1);

  if (!tx) notFound();

  const cats = await db
    .select()
    .from(categories)
    .orderBy(asc(categories.name));

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-semibold tracking-tight">Editar transação</h1>
      <div className="card-soft p-6 md:p-8">
        <TransactionForm categories={cats} transaction={tx} />
      </div>
    </div>
  );
}
