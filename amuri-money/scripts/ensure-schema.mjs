/**
 * Convergência de schema no boot.
 *
 * Roda antes do `next start`, dentro da máquina que tem o volume montado.
 * Não dá para usar `release_command` do Fly: máquinas de release não montam
 * volumes, então o script veria um banco vazio em /data e não o de verdade.
 *
 * Também não dá para usar o `migrate()` do drizzle: o banco foi criado com
 * `drizzle-kit push`, que não registra nada em `__drizzle_migrations`, então o
 * migrate tentaria aplicar a 0000 (`CREATE TABLE users`) num banco que já tem
 * as tabelas e falharia. Aqui a estratégia é: DDL idempotente para índices, e
 * verificação alta-e-clara de tabelas/colunas para que um deploy com schema
 * defasado apareça no `fly logs` em vez de virar 500 silencioso em toda request.
 *
 * É .mjs de propósito, e não .ts: o boot não pode depender do tsx, que é
 * devDependency. Assim um `npm ci --omit=dev` no futuro não derruba o app.
 */
import { createClient } from "@libsql/client";

/**
 * Tabelas que este script cria sozinho quando faltam, em vez de exigir db:push.
 * Só entram aqui tabelas novas e autocontidas (sem FK para tabela existente,
 * sem backfill), para que um deploy não precise de intervenção manual.
 */
const CREATABLE_TABLES = [
  {
    name: "month_snapshots",
    sql: "CREATE TABLE IF NOT EXISTS `month_snapshots` (`id` text PRIMARY KEY NOT NULL, `year` integer NOT NULL, `month` integer NOT NULL, `gateway_delta` real NOT NULL, `computed_at` integer NOT NULL)",
  },
];

const EXPECTED_INDEXES = [
  {
    name: "idx_transactions_date",
    sql: "CREATE INDEX IF NOT EXISTS `idx_transactions_date` ON `transactions` (`date`)",
  },
  {
    name: "idx_transactions_paid",
    sql: "CREATE INDEX IF NOT EXISTS `idx_transactions_paid` ON `transactions` (`paid`)",
  },
  {
    name: "idx_transactions_recurrence_parcel",
    sql: "CREATE INDEX IF NOT EXISTS `idx_transactions_recurrence_parcel` ON `transactions` (`recurrence_id`,`parcel_number`)",
  },
  {
    name: "idx_transactions_parent",
    sql: "CREATE INDEX IF NOT EXISTS `idx_transactions_parent` ON `transactions` (`parent_id`)",
  },
];

const EXPECTED_COLUMNS = {
  month_snapshots: ["id", "year", "month", "gateway_delta", "computed_at"],
  users: ["id", "email", "name", "password_hash", "created_at"],
  sessions: ["id", "user_id", "expires_at"],
  categories: ["id", "name", "type", "created_at"],
  cost_centers: ["id", "name", "created_at"],
  recurrences: [
    "id",
    "description",
    "amount",
    "category_id",
    "cost_center_id",
    "type",
    "start_date",
    "total_parcels",
    "day_of_month",
    "created_at",
  ],
  transactions: [
    "id",
    "date",
    "description",
    "amount",
    "category_id",
    "cost_center_id",
    "type",
    "paid",
    "recurrence_id",
    "parcel_number",
    "parent_id",
    "is_parent",
    "created_by",
    "created_at",
    "updated_at",
  ],
};

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error("[schema] DATABASE_URL não configurado.");
    process.exit(1);
  }

  const client = createClient({
    url,
    authToken: process.env.DATABASE_AUTH_TOKEN,
  });

  const created = [];

  for (const t of CREATABLE_TABLES) {
    const before = await client.execute(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
      [t.name],
    );
    if (before.rows.length > 0) continue;
    await client.execute(t.sql);
    created.push(`tabela ${t.name}`);
  }

  const tablesResult = await client.execute(
    "SELECT name FROM sqlite_master WHERE type = 'table'",
  );
  const tables = new Set(tablesResult.rows.map((r) => String(r.name)));

  // Banco novo (volume recém-criado): não há o que convergir, o db:push inicial
  // ainda precisa ser rodado à mão. Falhar aqui é melhor que subir e dar 500.
  const missingTables = Object.keys(EXPECTED_COLUMNS).filter(
    (t) => !tables.has(t),
  );
  if (missingTables.length > 0) {
    console.error(
      `[schema] tabelas ausentes: ${missingTables.join(", ")}. ` +
        "Rode `npm run db:push` contra este banco antes de subir.",
    );
    process.exit(1);
  }

  const problems = [];
  for (const [table, expected] of Object.entries(EXPECTED_COLUMNS)) {
    const info = await client.execute(`PRAGMA table_info(\`${table}\`)`);
    const present = new Set(info.rows.map((r) => String(r.name)));
    for (const col of expected) {
      if (!present.has(col)) problems.push(`${table}.${col}`);
    }
  }
  if (problems.length > 0) {
    console.error(
      `[schema] colunas ausentes: ${problems.join(", ")}. ` +
        "Rode `npm run db:push` contra este banco antes de subir.",
    );
    process.exit(1);
  }

  const indexResult = await client.execute(
    "SELECT name FROM sqlite_master WHERE type = 'index'",
  );
  const existingIndexes = new Set(indexResult.rows.map((r) => String(r.name)));

  for (const idx of EXPECTED_INDEXES) {
    if (existingIndexes.has(idx.name)) continue;
    await client.execute(idx.sql);
    created.push(`índice ${idx.name}`);
  }

  if (created.length > 0) {
    console.log(`[schema] criado: ${created.join(", ")}`);
  } else {
    console.log("[schema] ok, nada a fazer.");
  }
}

main().catch((e) => {
  console.error("[schema] falhou:", e);
  process.exit(1);
});
