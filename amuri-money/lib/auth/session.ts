import crypto from "node:crypto";
import { cookies } from "next/headers";
import { eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { sessions, users, type User } from "@/lib/db/schema";
import { SESSION_COOKIE } from "./constants";

export { SESSION_COOKIE };
const SESSION_DURATION_MS = 1000 * 60 * 60 * 24 * 30; // 30 dias

export async function createSession(userId: string) {
  const id = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + SESSION_DURATION_MS;
  await db.insert(sessions).values({ id, userId, expiresAt });
  return { id, expiresAt };
}

export async function setSessionCookie(sessionId: string, expiresAt: number) {
  const store = await cookies();
  store.set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    expires: new Date(expiresAt),
    path: "/",
  });
}

export async function clearSessionCookie() {
  const store = await cookies();
  store.delete(SESSION_COOKIE);
}

export async function getSession(): Promise<
  { sessionId: string; user: User } | null
> {
  const store = await cookies();
  const id = store.get(SESSION_COOKIE)?.value;
  if (!id) return null;

  const [row] = await db
    .select({ session: sessions, user: users })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(eq(sessions.id, id))
    .limit(1);

  if (!row) return null;
  if (row.session.expiresAt < Date.now()) {
    await db.delete(sessions).where(eq(sessions.id, id));
    return null;
  }

  return { sessionId: row.session.id, user: row.user };
}

export async function invalidateSession(sessionId: string) {
  await db.delete(sessions).where(eq(sessions.id, sessionId));
}

export async function requireUser(): Promise<User> {
  const session = await getSession();
  if (!session) throw new Error("Não autenticado");
  return session.user;
}
