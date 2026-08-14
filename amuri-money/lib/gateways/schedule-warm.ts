import "server-only";
import { nextCheckpointMs } from "./memory-cache";
import { warmGateways } from "./warm";

/**
 * Agendador do aquecimento de cache.
 *
 * Roda dentro do próprio processo do Next, e não como cron externo, porque o
 * banco e o cache vivem num volume Fly — que é single-attach. Uma máquina
 * separada de cron não conseguiria escrever no mesmo volume.
 */

/** Folga após o checkpoint, para aquecer já com o cache vencido. */
const AFTER_CHECKPOINT_MS = 60_000;

/** Espera após o boot, para não competir com o health check inicial. */
const AFTER_BOOT_MS = 20_000;

let started = false;

export function startWarmSchedule(): void {
  if (started) return;
  started = true;

  // O cache em memória nasce vazio a cada boot. Melhor pagar a sincronização
  // aqui que na primeira request de quem abrir o app.
  setTimeout(() => {
    void runWarm("boot");
  }, AFTER_BOOT_MS);

  scheduleNext();
  console.log("[warm] agendador iniciado");
}

function scheduleNext(): void {
  const delay = Math.max(
    nextCheckpointMs() - Date.now() + AFTER_CHECKPOINT_MS,
    AFTER_CHECKPOINT_MS,
  );
  setTimeout(() => {
    void runWarm("checkpoint");
    scheduleNext();
  }, delay);
  const emMinutos = Math.round(delay / 60_000);
  console.log(`[warm] próximo aquecimento em ~${emMinutos} min`);
}

async function runWarm(reason: string): Promise<void> {
  try {
    await warmGateways(reason);
  } catch (e) {
    // Aquecimento é otimização: falhar aqui não pode derrubar o processo.
    console.error("[warm] falhou:", e);
  }
}
