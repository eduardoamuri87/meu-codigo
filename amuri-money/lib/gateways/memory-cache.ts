import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { unlink, writeFile } from "node:fs/promises";
import path from "node:path";

type Entry<T> = { value: T; refreshedAt: number };

const CACHE_DIR = existsSync("/data") ? "/data" : path.join(process.cwd(), ".cache");
const CACHE_FILE = path.join(CACHE_DIR, "gateway-cache-v2.json");

if (!existsSync(CACHE_DIR)) {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
  } catch {}
}

const store: Map<string, Entry<unknown>> = new Map();
// mtime do arquivo na última vez que sincronizamos store ↔ disco.
// Usado para detectar quando outro processo apagou (clearGatewayCache) ou
// regravou o cache, mantendo réplicas consistentes em deploys multi-worker.
let lastSeenMtimeMs = 0;

function fileMtimeMs(): number {
  try {
    return statSync(CACHE_FILE).mtimeMs;
  } catch {
    return 0;
  }
}

function syncFromDisk() {
  const currentMtime = fileMtimeMs();
  if (currentMtime === lastSeenMtimeMs) return;

  store.clear();
  lastSeenMtimeMs = currentMtime;
  if (currentMtime === 0) return;

  try {
    const raw = readFileSync(CACHE_FILE, "utf8");
    for (const [k, v] of JSON.parse(raw) as Array<[string, Entry<unknown>]>) {
      store.set(k, v);
    }
  } catch {
    // leitura falhou — store fica vazio, próxima miss refetcha
  }
}

// Carrega o snapshot inicial do disco (se houver).
syncFromDisk();

function persist() {
  const data = JSON.stringify(Array.from(store.entries()));
  writeFile(CACHE_FILE, data)
    .then(() => {
      lastSeenMtimeMs = fileMtimeMs();
    })
    .catch(() => {});
}

export async function clearGatewayCache() {
  store.clear();
  lastSeenMtimeMs = 0;
  if (existsSync(CACHE_FILE)) {
    try {
      await unlink(CACHE_FILE);
    } catch {}
  }
}

const CHECKPOINT_HOURS_BRT = [10, 16] as const;

function brtParts(now: number): { y: number; m: number; d: number; h: number } {
  const fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Sao_Paulo",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    hour12: false,
  });
  const parts: Record<string, string> = {};
  for (const p of fmt.formatToParts(new Date(now))) parts[p.type] = p.value;
  const h = Number(parts.hour);
  return {
    y: Number(parts.year),
    m: Number(parts.month),
    d: Number(parts.day),
    h: h === 24 ? 0 : h,
  };
}

function brtMidnightUtcMs(y: number, m: number, d: number): number {
  // BRT é UTC-3 (sem DST desde 2019). 00:00 BRT do dia (y,m,d) = 03:00 UTC mesmo dia.
  return Date.UTC(y, m - 1, d, 3, 0, 0, 0);
}

export function mostRecentCheckpointMs(now: number = Date.now()): number {
  const { y, m, d, h } = brtParts(now);
  const midnight = brtMidnightUtcMs(y, m, d);
  for (let i = CHECKPOINT_HOURS_BRT.length - 1; i >= 0; i--) {
    if (h >= CHECKPOINT_HOURS_BRT[i]) {
      return midnight + CHECKPOINT_HOURS_BRT[i] * 3600 * 1000;
    }
  }
  // Antes do primeiro checkpoint do dia: vale o último de ontem.
  const lastHourYesterday =
    CHECKPOINT_HOURS_BRT[CHECKPOINT_HOURS_BRT.length - 1];
  const yesterdayMidnight = midnight - 86400 * 1000;
  return yesterdayMidnight + lastHourYesterday * 3600 * 1000;
}

export function withCheckpointCache<Args extends unknown[], T>(
  prefix: string,
  fn: (...args: Args) => Promise<T>,
): (...args: Args) => Promise<T> {
  return async (...args: Args) => {
    const key = prefix + ":" + JSON.stringify(args);
    const now = Date.now();
    const checkpoint = mostRecentCheckpointMs(now);
    syncFromDisk();
    const hit = store.get(key) as Entry<T> | undefined;
    if (hit && hit.refreshedAt >= checkpoint) return hit.value;
    const value = await fn(...args);
    store.set(key, { value, refreshedAt: now });
    persist();
    return value;
  };
}
