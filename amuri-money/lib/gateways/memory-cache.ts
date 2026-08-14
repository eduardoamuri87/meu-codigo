import { existsSync, mkdirSync } from "node:fs";
import { readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

type Entry<T> = { value: T; refreshedAt: number };

const CACHE_DIR = existsSync("/data") ? "/data" : path.join(process.cwd(), ".cache");
const CACHE_FILE = path.join(CACHE_DIR, "gateway-cache-v2.json");

if (!existsSync(CACHE_DIR)) {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
  } catch {}
}

// Prefixos que nunca vão para o disco: são listas brutas grandes cujo único
// consumidor são os agregados por mês, e esses sim são persistidos (~11 KB cada
// contra centenas de KB da lista). Sem isso o arquivo era reescrito e reparseado
// inteiro, com megabytes de JSON, num container de 512 MB.
//
// Medido em produção: 6,0 MB no total, sendo 5,53 MB só de
// stripe-charge-btxs-by-created-v1 acumulado por mês navegado, sem expurgo.
// Em dev, iugu-invoices-window-v1 chegava a 2,44 MB de 2,88 MB.
const MEMORY_ONLY_PREFIXES = [
  "iugu-invoices-window-v1",
  "stripe-charge-btxs-by-created-v1",
  "stripe-book-sessions-v2",
];

function isMemoryOnly(key: string): boolean {
  return MEMORY_ONLY_PREFIXES.some((p) => key.startsWith(p + ":"));
}

const store: Map<string, Entry<unknown>> = new Map();
// Buscas em andamento, por chave. É o que impede que as ~15 chamadas de gateway
// que o dashboard dispara em paralelo executem a mesma busca 5 a 10 vezes.
const inflight: Map<string, Promise<unknown>> = new Map();

// mtime do arquivo na última vez que sincronizamos store ↔ disco, usado para
// detectar quando outro processo apagou (clearGatewayCache) ou regravou o cache.
let lastSeenMtimeMs = 0;
let sawFile = false;

async function fileMtimeMs(): Promise<number> {
  try {
    return (await stat(CACHE_FILE)).mtimeMs;
  } catch {
    return 0;
  }
}

let syncing: Promise<void> | null = null;

function syncFromDisk(): Promise<void> {
  if (syncing) return syncing;
  syncing = readFromDisk().finally(() => {
    syncing = null;
  });
  return syncing;
}

async function readFromDisk(): Promise<void> {
  const currentMtime = await fileMtimeMs();
  if (currentMtime === lastSeenMtimeMs) return;
  lastSeenMtimeMs = currentMtime;

  // Arquivo sumiu: clearGatewayCache rodou em outro processo.
  if (currentMtime === 0) {
    if (sawFile) store.clear();
    sawFile = false;
    return;
  }
  sawFile = true;

  try {
    const raw = await readFile(CACHE_FILE, "utf8");
    const entries = JSON.parse(raw) as Array<[string, Entry<unknown>]>;
    // Merge em vez de clear: a escrita de outro processo não pode descartar o
    // que este processo acabou de calcular. Vence o refreshedAt mais novo.
    for (const [k, v] of entries) {
      if (isMemoryOnly(k)) continue;
      const mine = store.get(k);
      if (!mine || v.refreshedAt > mine.refreshedAt) store.set(k, v);
    }
  } catch {
    // Leitura ou parse falhou — mantém o que já está em memória e deixa o
    // próximo miss refetchar.
  }
}

const PERSIST_DEBOUNCE_MS = 500;
let persistTimer: ReturnType<typeof setTimeout> | null = null;
let persistChain: Promise<void> = Promise.resolve();

function schedulePersist() {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    persistChain = persistChain.then(writeSnapshot);
  }, PERSIST_DEBOUNCE_MS);
}

async function writeSnapshot(): Promise<void> {
  const entries = [...store.entries()].filter(([k]) => !isMemoryOnly(k));
  const data = JSON.stringify(entries);
  // tmp + rename: o rename é atômico no mesmo filesystem, então nenhum leitor
  // enxerga arquivo pela metade. O pid no nome evita que dois processos
  // disputem o mesmo tmp.
  const tmp = `${CACHE_FILE}.${process.pid}.tmp`;
  try {
    await writeFile(tmp, data);
    await rename(tmp, CACHE_FILE);
    lastSeenMtimeMs = await fileMtimeMs();
    sawFile = true;
  } catch (e) {
    console.error("[gateway-cache] persist falhou:", e);
    try {
      await unlink(tmp);
    } catch {}
  }
}

export async function clearGatewayCache() {
  store.clear();
  inflight.clear();
  lastSeenMtimeMs = 0;
  sawFile = false;
  try {
    await unlink(CACHE_FILE);
  } catch {}
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
    const checkpoint = mostRecentCheckpointMs();
    await syncFromDisk();

    const hit = store.get(key) as Entry<T> | undefined;
    if (hit && hit.refreshedAt >= checkpoint) return hit.value;

    const running = inflight.get(key) as Promise<T> | undefined;
    if (running) return running;

    const pending = fn(...args)
      .then((value) => {
        store.set(key, { value, refreshedAt: Date.now() });
        if (!isMemoryOnly(key)) schedulePersist();
        return value;
      })
      .finally(() => {
        inflight.delete(key);
      });
    inflight.set(key, pending);
    return pending;
  };
}
