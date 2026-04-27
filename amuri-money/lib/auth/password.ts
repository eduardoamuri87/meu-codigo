import { hash, compare } from "@node-rs/bcrypt";

export function hashPassword(password: string): Promise<string> {
  return hash(password, 10);
}

export function verifyPassword(
  password: string,
  passwordHash: string,
): Promise<boolean> {
  return compare(password, passwordHash);
}
