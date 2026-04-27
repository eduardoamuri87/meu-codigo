import crypto from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { and, asc, eq, gte, lte } from "drizzle-orm";
import { db } from "@/lib/db";
import { categories, costCenters, recurrences, transactions } from "@/lib/db/schema";
import {
  getStripeBooksMonthTotals,
  getStripeMonthTotals,
  listActiveStripeSubscriptions,
} from "@/lib/gateways/stripe";
import {
  getIuguMonthTotals,
  listIuguCustomersWithInstallments,
} from "@/lib/gateways/iugu";

type Txn = "receita" | "despesa";

const pad = (n: number) => String(n).padStart(2, "0");

function monthRange(year: number, month: number) {
  const firstDay = `${year}-${pad(month)}-01`;
  const lastDayNum = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const lastDay = `${year}-${pad(month)}-${pad(lastDayNum)}`;
  return { firstDay, lastDay };
}

function computeParcelDate(startDate: string, parcelIdx: number, dayOfMonth: number): string {
  if (parcelIdx === 1) return startDate;
  const [y, m] = startDate.split("-").map(Number);
  const totalIdx = y * 12 + (m - 1) + (parcelIdx - 1);
  const ty = Math.floor(totalIdx / 12);
  const tm = (totalIdx % 12) + 1;
  const daysInMonth = new Date(Date.UTC(ty, tm, 0)).getUTCDate();
  const day = Math.min(dayOfMonth, daysInMonth);
  return `${ty}-${pad(tm)}-${pad(day)}`;
}

async function resolveCategory(
  name: string | undefined,
  type: Txn,
  { allowMissing = false }: { allowMissing?: boolean } = {},
): Promise<string | null> {
  if (!name) return null;
  const rows = await db.select().from(categories).where(eq(categories.type, type));
  const match = rows.find((c) => c.name.toLowerCase() === name.trim().toLowerCase());
  if (!match) {
    if (allowMissing) return null;
    const available = rows.map((c) => c.name).join(", ") || "(nenhuma)";
    throw new Error(
      `Categoria "${name}" (${type}) não encontrada. Disponíveis: ${available}. Use create_category para criar.`,
    );
  }
  return match.id;
}

async function resolveCostCenter(
  name: string | undefined,
  { allowMissing = false }: { allowMissing?: boolean } = {},
): Promise<string | null> {
  if (!name) return null;
  const rows = await db.select().from(costCenters);
  const match = rows.find((c) => c.name.toLowerCase() === name.trim().toLowerCase());
  if (!match) {
    if (allowMissing) return null;
    const available = rows.map((c) => c.name).join(", ") || "(nenhum)";
    throw new Error(
      `Centro de custo "${name}" não encontrado. Disponíveis: ${available}. Use create_cost_center para criar.`,
    );
  }
  return match.id;
}

function textResult(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

const round = (n: number) => +n.toFixed(2);

async function computeMonthSummary(year: number, month: number) {
  const { firstDay, lastDay } = monthRange(year, month);
  const [dbRows, stripe, iugu, books] = await Promise.all([
    db
      .select({ amount: transactions.amount, type: transactions.type })
      .from(transactions)
      .where(
        and(gte(transactions.date, firstDay), lte(transactions.date, lastDay)),
      ),
    getStripeMonthTotals(year, month),
    getIuguMonthTotals(year, month),
    getStripeBooksMonthTotals(year, month),
  ]);

  let dbReceita = 0;
  let dbDespesa = 0;
  for (const r of dbRows) {
    if (r.type === "receita") dbReceita += r.amount;
    else dbDespesa += r.amount;
  }

  const stripeTotal = stripe.recebido.total + stripe.aReceber.total;
  const iuguTotal = iugu.recebido.total + iugu.aReceber.total;
  const booksTotal = books.recebido.total + books.aReceber.total;
  const receitaTotal = dbReceita + stripeTotal + iuguTotal + booksTotal;
  const saldoProjetado = receitaTotal - dbDespesa;

  return {
    month,
    year,
    db: {
      receita: round(dbReceita),
      despesa: round(dbDespesa),
      saldo: round(dbReceita - dbDespesa),
      count: dbRows.length,
    },
    stripe: {
      recebido: round(stripe.recebido.total),
      aReceber: round(stripe.aReceber.total),
      total: round(stripeTotal),
      error: stripe.error,
    },
    iugu: {
      recebido: round(iugu.recebido.total),
      aReceber: round(iugu.aReceber.total),
      total: round(iuguTotal),
      error: iugu.error,
    },
    stripeBooks: {
      recebido: round(books.recebido.total),
      aReceber: round(books.aReceber.total),
      total: round(booksTotal),
      error: books.error,
    },
    consolidado: {
      receitaTotal: round(receitaTotal),
      despesaTotal: round(dbDespesa),
      saldoProjetado: round(saldoProjetado),
    },
  };
}

export function registerTools(server: McpServer) {
  server.registerTool(
    "list_transactions",
    {
      title: "Listar transações",
      description:
        "Lista transações de um mês específico com totais (receita, despesa, saldo). Categoria retornada por nome.",
      inputSchema: {
        month: z.number().int().min(1).max(12),
        year: z.number().int().min(2000).max(2100),
        type: z.enum(["receita", "despesa"]).optional(),
        paid: z.boolean().optional(),
      },
    },
    async ({ month, year, type, paid }) => {
      const { firstDay, lastDay } = monthRange(year, month);
      const conds = [gte(transactions.date, firstDay), lte(transactions.date, lastDay)];
      if (type) conds.push(eq(transactions.type, type));
      if (paid !== undefined) conds.push(eq(transactions.paid, paid));

      const rows = await db
        .select({
          id: transactions.id,
          date: transactions.date,
          description: transactions.description,
          amount: transactions.amount,
          type: transactions.type,
          paid: transactions.paid,
          parcelNumber: transactions.parcelNumber,
          recurrenceId: transactions.recurrenceId,
          categoryName: categories.name,
          costCenterName: costCenters.name,
        })
        .from(transactions)
        .leftJoin(categories, eq(transactions.categoryId, categories.id))
        .leftJoin(costCenters, eq(transactions.costCenterId, costCenters.id))
        .where(and(...conds))
        .orderBy(asc(transactions.date));

      let receita = 0;
      let despesa = 0;
      for (const r of rows) {
        if (r.type === "receita") receita += r.amount;
        else despesa += r.amount;
      }

      return textResult({
        month,
        year,
        totals: {
          receita: +receita.toFixed(2),
          despesa: +despesa.toFixed(2),
          saldo: +(receita - despesa).toFixed(2),
        },
        count: rows.length,
        transactions: rows,
      });
    },
  );

  server.registerTool(
    "create_transaction",
    {
      title: "Criar transação",
      description:
        "Cria uma transação única (não recorrente). Informe `category` pelo nome — deve já existir com o tipo correto. `cost_center` opcional, por nome (faz sentido pra despesas). Se `allow_missing_category` ou `allow_missing_cost_center` for true, aceita nome inexistente e cria sem o vínculo (útil pra imports em massa).",
      inputSchema: {
        date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "formato YYYY-MM-DD"),
        description: z.string().min(1),
        amount: z.number().nonnegative(),
        type: z.enum(["receita", "despesa"]),
        category: z.string().optional(),
        cost_center: z.string().optional(),
        paid: z.boolean().default(false),
        allow_missing_category: z.boolean().default(false),
        allow_missing_cost_center: z.boolean().default(false),
      },
    },
    async ({
      date,
      description,
      amount,
      type,
      category,
      cost_center,
      paid,
      allow_missing_category,
      allow_missing_cost_center,
    }) => {
      const categoryId = await resolveCategory(category, type, {
        allowMissing: allow_missing_category,
      });
      const costCenterId = await resolveCostCenter(cost_center, {
        allowMissing: allow_missing_cost_center,
      });
      const id = crypto.randomUUID();
      const now = Date.now();
      await db.insert(transactions).values({
        id,
        date,
        description,
        amount,
        type,
        categoryId,
        costCenterId,
        paid,
        createdAt: now,
        updatedAt: now,
      });
      return textResult({ ok: true, id });
    },
  );

  server.registerTool(
    "update_transaction",
    {
      title: "Atualizar transação",
      description:
        "Atualiza campos de uma transação existente. Campos omitidos permanecem inalterados. Categoria e centro de custo por nome (passe null para remover o vínculo).",
      inputSchema: {
        id: z.string().min(1),
        date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
        description: z.string().min(1).optional(),
        amount: z.number().nonnegative().optional(),
        type: z.enum(["receita", "despesa"]).optional(),
        category: z.string().nullable().optional(),
        cost_center: z.string().nullable().optional(),
        paid: z.boolean().optional(),
      },
    },
    async ({ id, date, description, amount, type, category, cost_center, paid }) => {
      const [current] = await db
        .select({ type: transactions.type, categoryId: transactions.categoryId })
        .from(transactions)
        .where(eq(transactions.id, id))
        .limit(1);
      if (!current) throw new Error(`Transação ${id} não encontrada.`);

      const nextType = type ?? current.type;
      const patch: Record<string, unknown> = { updatedAt: Date.now() };
      if (date !== undefined) patch.date = date;
      if (description !== undefined) patch.description = description;
      if (amount !== undefined) patch.amount = amount;
      if (type !== undefined) patch.type = type;
      if (paid !== undefined) patch.paid = paid;
      if (category !== undefined) {
        patch.categoryId = category === null ? null : await resolveCategory(category, nextType);
      } else if (type !== undefined && type !== current.type && current.categoryId) {
        patch.categoryId = null;
      }
      if (cost_center !== undefined) {
        patch.costCenterId =
          cost_center === null ? null : await resolveCostCenter(cost_center);
      }

      await db.update(transactions).set(patch).where(eq(transactions.id, id));
      return textResult({ ok: true, id });
    },
  );

  server.registerTool(
    "delete_transaction",
    {
      title: "Deletar transação",
      description:
        "Deleta uma transação. Scope 'futures' deleta todas as parcelas futuras não pagas da mesma recorrência (a partir da data da transação informada).",
      inputSchema: {
        id: z.string().min(1),
        scope: z.enum(["single", "futures"]).default("single"),
      },
    },
    async ({ id, scope }) => {
      if (scope === "futures") {
        const [tx] = await db
          .select({ recurrenceId: transactions.recurrenceId, date: transactions.date })
          .from(transactions)
          .where(eq(transactions.id, id))
          .limit(1);
        if (tx?.recurrenceId) {
          const result = await db
            .delete(transactions)
            .where(
              and(
                eq(transactions.recurrenceId, tx.recurrenceId),
                gte(transactions.date, tx.date),
                eq(transactions.paid, false),
              ),
            );
          return textResult({ ok: true, scope, deleted: result.rowsAffected ?? null });
        }
      }
      const result = await db.delete(transactions).where(eq(transactions.id, id));
      return textResult({ ok: true, scope, deleted: result.rowsAffected ?? null });
    },
  );

  server.registerTool(
    "toggle_paid",
    {
      title: "Marcar pago/não pago",
      description: "Atualiza o campo `paid` de uma transação.",
      inputSchema: {
        id: z.string().min(1),
        paid: z.boolean(),
      },
    },
    async ({ id, paid }) => {
      await db
        .update(transactions)
        .set({ paid, updatedAt: Date.now() })
        .where(eq(transactions.id, id));
      return textResult({ ok: true, id, paid });
    },
  );

  server.registerTool(
    "list_categories",
    {
      title: "Listar categorias",
      description: "Lista categorias cadastradas. Filtro opcional por tipo.",
      inputSchema: {
        type: z.enum(["receita", "despesa"]).optional(),
      },
    },
    async ({ type }) => {
      const rows = type
        ? await db.select().from(categories).where(eq(categories.type, type))
        : await db.select().from(categories);
      rows.sort((a, b) => a.name.localeCompare(b.name, "pt-BR"));
      return textResult({ count: rows.length, categories: rows });
    },
  );

  server.registerTool(
    "create_category",
    {
      title: "Criar categoria",
      description: "Cria uma nova categoria com nome e tipo (receita ou despesa).",
      inputSchema: {
        name: z.string().min(1),
        type: z.enum(["receita", "despesa"]),
      },
    },
    async ({ name, type }) => {
      const id = crypto.randomUUID();
      await db.insert(categories).values({ id, name: name.trim(), type, createdAt: Date.now() });
      return textResult({ ok: true, id, name, type });
    },
  );

  server.registerTool(
    "assign_cost_center",
    {
      title: "Atribuir centro de custo a uma transação",
      description:
        "Atribui (ou remove) o centro de custo de uma transação existente. Passe `cost_center` pelo nome para vincular, ou `null` para desvincular. Use quando o usuário pedir explicitamente para classificar uma transação por centro de custo.",
      inputSchema: {
        transaction_id: z.string().min(1),
        cost_center: z.string().nullable(),
        allow_missing_cost_center: z.boolean().default(false),
      },
    },
    async ({ transaction_id, cost_center, allow_missing_cost_center }) => {
      const [current] = await db
        .select({ id: transactions.id })
        .from(transactions)
        .where(eq(transactions.id, transaction_id))
        .limit(1);
      if (!current) throw new Error(`Transação ${transaction_id} não encontrada.`);

      const costCenterId =
        cost_center === null
          ? null
          : await resolveCostCenter(cost_center, {
              allowMissing: allow_missing_cost_center,
            });

      await db
        .update(transactions)
        .set({ costCenterId, updatedAt: Date.now() })
        .where(eq(transactions.id, transaction_id));

      return textResult({
        ok: true,
        id: transaction_id,
        costCenterId,
      });
    },
  );

  server.registerTool(
    "assign_cost_center_by_category",
    {
      title: "Atribuir centro de custo a todas as transações de uma categoria",
      description:
        "Atualiza em massa todas as transações que tenham determinada categoria, atribuindo (ou removendo) o centro de custo. Útil pra organização retroativa. `cost_center` null remove o vínculo. `type` é opcional pra desambiguar caso exista categoria homônima de receita e despesa. Pode opcionalmente limitar por intervalo de datas (`from_date`, `to_date` em YYYY-MM-DD).",
      inputSchema: {
        category: z.string().min(1),
        cost_center: z.string().nullable(),
        type: z.enum(["receita", "despesa"]).optional(),
        from_date: z
          .string()
          .regex(/^\d{4}-\d{2}-\d{2}$/, "formato YYYY-MM-DD")
          .optional(),
        to_date: z
          .string()
          .regex(/^\d{4}-\d{2}-\d{2}$/, "formato YYYY-MM-DD")
          .optional(),
      },
    },
    async ({ category, cost_center, type, from_date, to_date }) => {
      const catRows = await db.select().from(categories);
      const matching = catRows.filter(
        (c) =>
          c.name.toLowerCase() === category.trim().toLowerCase() &&
          (!type || c.type === type),
      );
      if (matching.length === 0) {
        throw new Error(
          `Categoria "${category}"${type ? ` (${type})` : ""} não encontrada.`,
        );
      }
      if (matching.length > 1 && !type) {
        throw new Error(
          `Existe categoria "${category}" para receita e despesa. Informe \`type\` para desambiguar.`,
        );
      }
      const categoryIds = matching.map((c) => c.id);

      const costCenterId =
        cost_center === null ? null : await resolveCostCenter(cost_center);

      const conds = [];
      if (categoryIds.length === 1) {
        conds.push(eq(transactions.categoryId, categoryIds[0]));
      } else {
        // múltiplos ids (caso muito raro, defensivo)
        conds.push(eq(transactions.categoryId, categoryIds[0]));
      }
      if (from_date) conds.push(gte(transactions.date, from_date));
      if (to_date) conds.push(lte(transactions.date, to_date));

      const result = await db
        .update(transactions)
        .set({ costCenterId, updatedAt: Date.now() })
        .where(and(...conds));

      return textResult({
        ok: true,
        category,
        type: matching[0].type,
        cost_center,
        affected: result.rowsAffected ?? null,
        from_date,
        to_date,
      });
    },
  );

  server.registerTool(
    "list_cost_centers",
    {
      title: "Listar centros de custo",
      description: "Lista todos os centros de custo cadastrados.",
      inputSchema: {},
    },
    async () => {
      const rows = await db.select().from(costCenters);
      rows.sort((a, b) => a.name.localeCompare(b.name, "pt-BR"));
      return textResult({ count: rows.length, costCenters: rows });
    },
  );

  server.registerTool(
    "create_cost_center",
    {
      title: "Criar centro de custo",
      description: "Cria um novo centro de custo com o nome informado.",
      inputSchema: {
        name: z.string().min(1),
      },
    },
    async ({ name }) => {
      const id = crypto.randomUUID();
      await db
        .insert(costCenters)
        .values({ id, name: name.trim(), createdAt: Date.now() });
      return textResult({ ok: true, id, name });
    },
  );

  server.registerTool(
    "list_recurrences",
    {
      title: "Listar recorrências",
      description: "Lista todas as recorrências cadastradas com categoria e centro de custo resolvidos por nome.",
      inputSchema: {},
    },
    async () => {
      const rows = await db
        .select({
          id: recurrences.id,
          description: recurrences.description,
          amount: recurrences.amount,
          type: recurrences.type,
          startDate: recurrences.startDate,
          totalParcels: recurrences.totalParcels,
          dayOfMonth: recurrences.dayOfMonth,
          categoryName: categories.name,
          costCenterName: costCenters.name,
        })
        .from(recurrences)
        .leftJoin(categories, eq(recurrences.categoryId, categories.id))
        .leftJoin(costCenters, eq(recurrences.costCenterId, costCenters.id));
      return textResult({ count: rows.length, recurrences: rows });
    },
  );

  server.registerTool(
    "create_recurrence",
    {
      title: "Criar recorrência",
      description:
        "Cria uma recorrência com N parcelas mensais (2 a 240). Gera automaticamente todas as transações associadas, não pagas. `cost_center` opcional, por nome (faz sentido pra despesas).",
      inputSchema: {
        description: z.string().min(1),
        amount: z.number().nonnegative(),
        type: z.enum(["receita", "despesa"]),
        category: z.string().optional(),
        cost_center: z.string().optional(),
        start_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "formato YYYY-MM-DD"),
        total_parcels: z.number().int().min(2).max(240),
        day_of_month: z.number().int().min(1).max(31),
      },
    },
    async ({
      description,
      amount,
      type,
      category,
      cost_center,
      start_date,
      total_parcels,
      day_of_month,
    }) => {
      const categoryId = await resolveCategory(category, type);
      const costCenterId = await resolveCostCenter(cost_center);
      const now = Date.now();
      const recurrenceId = crypto.randomUUID();

      await db.insert(recurrences).values({
        id: recurrenceId,
        description,
        amount,
        categoryId,
        costCenterId,
        type,
        startDate: start_date,
        totalParcels: total_parcels,
        dayOfMonth: day_of_month,
        createdAt: now,
      });

      const rows = Array.from({ length: total_parcels }, (_, i) => ({
        id: crypto.randomUUID(),
        date: computeParcelDate(start_date, i + 1, day_of_month),
        description,
        amount,
        categoryId,
        costCenterId,
        type,
        paid: false,
        recurrenceId,
        parcelNumber: i + 1,
        createdAt: now,
        updatedAt: now,
      }));

      await db.insert(transactions).values(rows);

      return textResult({
        ok: true,
        recurrence_id: recurrenceId,
        parcels_created: rows.length,
        first_date: rows[0].date,
        last_date: rows[rows.length - 1].date,
      });
    },
  );

  server.registerTool(
    "get_stripe_month",
    {
      title: "Totais Stripe do mês",
      description:
        "Busca assinaturas ativas no Stripe e computa valores recebidos e a receber no mês informado (líquido de taxa estimada). Requer STRIPE_API_TOKEN no ambiente.",
      inputSchema: {
        month: z.number().int().min(1).max(12),
        year: z.number().int().min(2000).max(2100),
      },
    },
    async ({ month, year }) => {
      const totals = await getStripeMonthTotals(year, month);
      return textResult({ month, year, ...totals });
    },
  );

  server.registerTool(
    "get_stripe_books_month",
    {
      title: "Totais Stripe (vendas de livros) do mês",
      description:
        "Soma as vendas one-off (não-assinatura) do Stripe liquidadas no mês informado, separando recebido (já caiu no banco) e a receber (available_on > hoje). Use quando o usuário perguntar sobre vendas do livro 'Dinheiro sem medo'.",
      inputSchema: {
        month: z.number().int().min(1).max(12),
        year: z.number().int().min(2000).max(2100),
      },
    },
    async ({ month, year }) => {
      const totals = await getStripeBooksMonthTotals(year, month);
      return textResult({ month, year, ...totals });
    },
  );

  server.registerTool(
    "get_iugu_month",
    {
      title: "Totais Iugu do mês",
      description:
        "Busca faturas pagas na Iugu e computa valores recebidos e a receber no mês informado (a partir das datas de liquidação financeira das parcelas). Requer IUGU_API_TOKEN no ambiente.",
      inputSchema: {
        month: z.number().int().min(1).max(12),
        year: z.number().int().min(2000).max(2100),
      },
    },
    async ({ month, year }) => {
      const totals = await getIuguMonthTotals(year, month);
      return textResult({ month, year, ...totals });
    },
  );

  server.registerTool(
    "list_stripe_subscriptions",
    {
      title: "Listar assinaturas ativas do Stripe",
      description:
        "Lista todas as assinaturas Stripe atualmente ativas, com cliente, produto, valor mensal (bruto e líquido de taxa estimada), intervalo, data de início, próxima cobrança, e se/quando cancela. Use para responder 'quem são meus clientes ativos' ou 'qual minha MRR'.",
      inputSchema: {},
    },
    async () => {
      const data = await listActiveStripeSubscriptions();
      return textResult(data);
    },
  );

  server.registerTool(
    "list_iugu_customers_with_installments",
    {
      title: "Clientes Iugu com parcelamentos ativos",
      description:
        "Lista clientes da Iugu que ainda têm parcelas futuras não liquidadas (return_date > hoje e status != paid). Para cada cliente: quantas parcelas restantes, valor total a receber, próxima e última data de liquidação. Use para saber quem ainda está pagando e quanto falta entrar.",
      inputSchema: {},
    },
    async () => {
      const data = await listIuguCustomersWithInstallments();
      return textResult(data);
    },
  );

  server.registerTool(
    "get_month_summary",
    {
      title: "Resumo financeiro do mês",
      description:
        "Retorna o saldo consolidado do mês combinando: transações registradas no DB (receita/despesa), receitas do Stripe (recebido + a receber, líquido de taxa) e receitas da Iugu (recebido + a receber). Use esta tool quando o usuário perguntar sobre saldo geral, projeção de fim de mês ou resumo financeiro — evita ter que agregar manualmente chamando 3 tools separadas.",
      inputSchema: {
        month: z.number().int().min(1).max(12),
        year: z.number().int().min(2000).max(2100),
      },
    },
    async ({ month, year }) => {
      return textResult(await computeMonthSummary(year, month));
    },
  );

  server.registerTool(
    "get_year_projection",
    {
      title: "Projeção financeira do ano com cascata",
      description:
        "Retorna o resumo mês-a-mês do ano com cascata de saldo: cada mês tem saldoInicial (saldo final do mês anterior), delta do mês, e saldoFinal. Por padrão a cascata começa no mês atual (ou janeiro se o ano for futuro), mas start_month permite controlar. Use quando o usuário perguntar sobre o ano, tendência mensal, ou saldo projetado num mês futuro — evita chamar get_month_summary 12 vezes e já traz o saldo cascateado como a UI mostra.",
      inputSchema: {
        year: z.number().int().min(2000).max(2100),
        start_month: z.number().int().min(1).max(12).optional(),
        start_balance: z.number().optional(),
      },
    },
    async ({ year, start_month, start_balance }) => {
      const today = new Date();
      const currentYear = today.getUTCFullYear();
      const currentMonth = today.getUTCMonth() + 1;
      const effectiveStart =
        start_month ?? (year === currentYear ? currentMonth : 1);
      const initialBalance = start_balance ?? 0;

      const monthsToCompute: number[] = [];
      for (let m = effectiveStart; m <= 12; m++) monthsToCompute.push(m);

      const summaries = await Promise.all(
        monthsToCompute.map((m) => computeMonthSummary(year, m)),
      );

      const months: Array<{
        month: number;
        year: number;
        delta: number;
        saldoInicial: number;
        saldoFinal: number;
        db: (typeof summaries)[number]["db"];
        stripe: (typeof summaries)[number]["stripe"];
        iugu: (typeof summaries)[number]["iugu"];
        stripeBooks: (typeof summaries)[number]["stripeBooks"];
      }> = [];

      let running = initialBalance;
      let receitaTotalAno = 0;
      let despesaTotalAno = 0;

      for (const s of summaries) {
        const delta =
          s.consolidado.receitaTotal - s.consolidado.despesaTotal;
        const saldoInicial = running;
        const saldoFinal = saldoInicial + delta;
        running = saldoFinal;
        receitaTotalAno += s.consolidado.receitaTotal;
        despesaTotalAno += s.consolidado.despesaTotal;
        months.push({
          month: s.month,
          year: s.year,
          delta: round(delta),
          saldoInicial: round(saldoInicial),
          saldoFinal: round(saldoFinal),
          db: s.db,
          stripe: s.stripe,
          iugu: s.iugu,
          stripeBooks: s.stripeBooks,
        });
      }

      return textResult({
        year,
        startMonth: effectiveStart,
        startBalance: round(initialBalance),
        months,
        anual: {
          receitaTotal: round(receitaTotalAno),
          despesaTotal: round(despesaTotalAno),
          saldoFinal: round(running),
        },
      });
    },
  );
}
