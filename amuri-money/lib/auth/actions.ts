"use server";

import { redirect } from "next/navigation";
import { eq } from "drizzle-orm";
import { db } from "@/lib/db";
import { users } from "@/lib/db/schema";
import { verifyPassword } from "./password";
import {
  clearSessionCookie,
  createSession,
  getSession,
  invalidateSession,
  setSessionCookie,
} from "./session";

export type LoginState = { error?: string };

export async function loginAction(
  _prev: LoginState | undefined,
  formData: FormData,
): Promise<LoginState> {
  const email = String(formData.get("email") ?? "").trim().toLowerCase();
  const password = String(formData.get("password") ?? "");

  if (!email || !password) {
    return { error: "Preencha email e senha." };
  }

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (!user) return { error: "Email ou senha inválidos." };

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) return { error: "Email ou senha inválidos." };

  const session = await createSession(user.id);
  await setSessionCookie(session.id, session.expiresAt);

  redirect("/");
}

export async function logoutAction() {
  const current = await getSession();
  if (current) await invalidateSession(current.sessionId);
  await clearSessionCookie();
  redirect("/login");
}
