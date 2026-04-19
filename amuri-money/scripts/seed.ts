import crypto from "node:crypto";
import { eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { users } from "@/lib/db/schema";
import { hashPassword } from "@/lib/auth/password";

const SEED_USERS = [
  { email: "eduardo@amuri.com.br", name: "Eduardo" },
  { email: "helo@amuri.com.br", name: "Helô" },
];

const DEFAULT_PASSWORD = "trocar123";

async function main() {
  const hash = await hashPassword(DEFAULT_PASSWORD);

  for (const u of SEED_USERS) {
    const [existing] = await db
      .select()
      .from(users)
      .where(eq(users.email, u.email))
      .limit(1);

    if (existing) {
      console.log(`já existe: ${u.email}`);
      continue;
    }

    await db.insert(users).values({
      id: crypto.randomUUID(),
      email: u.email,
      name: u.name,
      passwordHash: hash,
      createdAt: Date.now(),
    });
    console.log(`criado: ${u.email} (senha: ${DEFAULT_PASSWORD})`);
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
