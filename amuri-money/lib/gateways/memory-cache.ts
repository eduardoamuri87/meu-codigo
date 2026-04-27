import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { unlink, writeFile } from "node:fs/promises";
import path from "node:path";

type Entry<T> = { value: T; expiresAt: number };

const CACHE_DIR = existsSync("/data") ? "/data" : path.join(process.cwd(), ".cache");
const CACHE_FILE = path.join(CACHE_DIR, "gateway-cache.json");

if (!existsSync(CACHE_DIR)) {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
  } catch {}
}

const store: Map<string, Entry<unknown>> = (() => {
  if (!existsSync(CACHE_FILE)) return new Map();
  try {
    const raw = readFileSync(CACHE_FILE, "utf8");
    return new Map(JSON.parse(raw) as Array<[string, Entry<unknown>]>);
  } catch {
    return new Map();
  }
})();

function persist() {
  const data = JSON.stringify(Array.from(store.entries()));
  writeFile(CACHE_FILE, data).catch(() => {});
}

export async function clearGatewayCache() {
  store.clear();
  if (existsSync(CACHE_FILE)) {
    try {
      await unlink(CACHE_FILE);
    } catch {}
  }
}

export function withTtlCache<Args extends unknown[], T>(
  prefix: string,
  ttlMs: number,
  fn: (...args: Args) => Promise<T>,
): (...args: Args) => Promise<T> {
  return async (...args: Args) => {
    const key = prefix + ":" + JSON.stringify(args);
    const now = Date.now();
    const hit = store.get(key) as Entry<T> | undefined;
    if (hit && hit.expiresAt > now) return hit.value;
    const value = await fn(...args);
    store.set(key, { value, expiresAt: now + ttlMs });
    persist();
    return value;
  };
}
