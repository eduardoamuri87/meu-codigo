/**
 * `register` roda uma vez por instância do servidor, e precisa retornar antes de
 * o servidor aceitar requests — então aqui só agendamos, nunca aguardamos o
 * aquecimento em si.
 */
export function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  // Durante `next build` o Next também inicia workers; não queremos bater em
  // Iugu/Stripe no build.
  if (process.env.NEXT_PHASE === "phase-production-build") return;

  import("./lib/gateways/schedule-warm")
    .then((m) => m.startWarmSchedule())
    .catch((e) => console.error("[warm] agendador não iniciou:", e));
}
