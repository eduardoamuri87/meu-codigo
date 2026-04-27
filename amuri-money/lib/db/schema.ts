import { sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
  real,
  sqliteTable,
  text,
} from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  name: text("name").notNull(),
  passwordHash: text("password_hash").notNull(),
  createdAt: integer("created_at").notNull(),
});

export const sessions = sqliteTable("sessions", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  expiresAt: integer("expires_at").notNull(),
});

export const categories = sqliteTable(
  "categories",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    type: text("type", { enum: ["receita", "despesa"] }).notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    check("categories_type_check", sql`${t.type} IN ('receita', 'despesa')`),
  ],
);

export const costCenters = sqliteTable("cost_centers", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  createdAt: integer("created_at").notNull(),
});

export const recurrences = sqliteTable(
  "recurrences",
  {
    id: text("id").primaryKey(),
    description: text("description").notNull(),
    amount: real("amount").notNull(),
    categoryId: text("category_id").references(() => categories.id),
    costCenterId: text("cost_center_id").references(() => costCenters.id),
    type: text("type", { enum: ["receita", "despesa"] }).notNull(),
    startDate: text("start_date").notNull(),
    totalParcels: integer("total_parcels"),
    dayOfMonth: integer("day_of_month").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    check("recurrences_type_check", sql`${t.type} IN ('receita', 'despesa')`),
  ],
);

export const transactions = sqliteTable(
  "transactions",
  {
    id: text("id").primaryKey(),
    date: text("date").notNull(),
    description: text("description").notNull(),
    amount: real("amount").notNull(),
    categoryId: text("category_id").references(() => categories.id),
    costCenterId: text("cost_center_id").references(() => costCenters.id),
    type: text("type", { enum: ["receita", "despesa"] }).notNull(),
    paid: integer("paid", { mode: "boolean" }).notNull().default(false),
    recurrenceId: text("recurrence_id").references(() => recurrences.id),
    parcelNumber: integer("parcel_number"),
    createdBy: text("created_by").references(() => users.id),
    createdAt: integer("created_at").notNull(),
    updatedAt: integer("updated_at").notNull(),
  },
  (t) => [
    index("idx_transactions_date").on(t.date),
    index("idx_transactions_paid").on(t.paid),
    index("idx_transactions_recurrence_parcel").on(
      t.recurrenceId,
      t.parcelNumber,
    ),
    check("transactions_type_check", sql`${t.type} IN ('receita', 'despesa')`),
  ],
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type Category = typeof categories.$inferSelect;
export type NewCategory = typeof categories.$inferInsert;
export type CostCenter = typeof costCenters.$inferSelect;
export type NewCostCenter = typeof costCenters.$inferInsert;
export type Recurrence = typeof recurrences.$inferSelect;
export type NewRecurrence = typeof recurrences.$inferInsert;
export type Transaction = typeof transactions.$inferSelect;
export type NewTransaction = typeof transactions.$inferInsert;
