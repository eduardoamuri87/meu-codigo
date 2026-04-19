import { asc } from "drizzle-orm";
import { db } from "@/lib/db";
import { categories } from "@/lib/db/schema";
import { CategoriesClient } from "./categories-client";

export default async function CategoriasPage() {
  const rows = await db
    .select()
    .from(categories)
    .orderBy(asc(categories.type), asc(categories.name));

  return <CategoriesClient categories={rows} />;
}
