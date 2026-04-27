import { asc } from "drizzle-orm";
import { db } from "@/lib/db";
import { costCenters } from "@/lib/db/schema";
import { CostCentersClient } from "./cost-centers-client";

export default async function CentrosDeCustoPage() {
  const rows = await db
    .select()
    .from(costCenters)
    .orderBy(asc(costCenters.name));

  return <CostCentersClient costCenters={rows} />;
}
