import { asc } from "drizzle-orm";
import { db } from "@/lib/db";
import { categories } from "@/lib/db/schema";
import { TransactionForm } from "../transaction-form";

export default async function NovaTransacaoPage() {
  const cats = await db
    .select()
    .from(categories)
    .orderBy(asc(categories.name));

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-semibold tracking-tight">Nova transação</h1>
      <div className="card-soft p-6 md:p-8">
        <TransactionForm categories={cats} />
      </div>
    </div>
  );
}
