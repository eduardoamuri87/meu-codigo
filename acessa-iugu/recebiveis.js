// Lista faturas pagas (recebíveis) na Iugu por mês.
// Uso: node recebiveis.js 2026-04
//      node recebiveis.js          (mês atual)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TOKEN = readFileSync(join(__dirname, "token.txt"), "utf8").trim();

const arg = process.argv[2];
const hoje = new Date();
const mes = arg || `${hoje.getFullYear()}-${String(hoje.getMonth() + 1).padStart(2, "0")}`;

if (!/^\d{4}-\d{2}$/.test(mes)) {
  console.error("Mês inválido. Use AAAA-MM, ex: 2026-04");
  process.exit(1);
}

const [ano, m] = mes.split("-").map(Number);
const primeiro = `${mes}-01`;
const ultimoDia = new Date(ano, m, 0).getDate();
const ultimo = `${mes}-${String(ultimoDia).padStart(2, "0")}`;

const auth = "Basic " + Buffer.from(TOKEN + ":").toString("base64");
const brl = (c) => (c / 100).toLocaleString("pt-BR", { style: "currency", currency: "BRL" });

async function buscar() {
  const limit = 100;
  let start = 0;
  let total = 0;
  const faturas = [];

  while (true) {
    const url = new URL("https://api.iugu.com/v1/invoices");
    url.searchParams.set("limit", limit);
    url.searchParams.set("start", start);
    url.searchParams.set("status_filter", "paid");
    url.searchParams.set("paid_at_from", primeiro);
    url.searchParams.set("paid_at_to", ultimo);
    url.searchParams.set("sortBy[paid_at]", "asc");

    const resp = await fetch(url, { headers: { Authorization: auth } });
    if (!resp.ok) {
      console.error(`HTTP ${resp.status}: ${await resp.text()}`);
      process.exit(1);
    }
    const data = await resp.json();
    total = data.totalItems ?? 0;
    faturas.push(...(data.items || []));
    if (faturas.length >= total || (data.items || []).length === 0) break;
    start += limit;
  }

  console.log(`\nRecebíveis pagos entre ${primeiro} e ${ultimo}\n`);

  if (faturas.length === 0) {
    console.log("Nenhuma fatura paga encontrada.");
    return;
  }

  const linhas = faturas.map((f) => {
    const taxa = (f.taxes_paid_cents || 0) + (f.commission_cents || 0);
    const bruto = f.total_paid_cents || f.total_cents || 0;
    return {
      "Pago em": (f.paid_at || "").slice(0, 10),
      Cliente: (f.payer_name || f.customer_name || f.email || "-").slice(0, 35),
      Bruto: brl(bruto),
      Taxas: brl(taxa),
      Líquido: brl(bruto - taxa),
    };
  });

  console.table(linhas);

  const soma = faturas.reduce((a, f) => a + (f.total_paid_cents || f.total_cents || 0), 0);
  const taxas = faturas.reduce((a, f) => a + (f.taxes_paid_cents || 0) + (f.commission_cents || 0), 0);

  console.log(`\nTotal: ${faturas.length} faturas`);
  console.log(`Bruto:   ${brl(soma)}`);
  console.log(`Taxas:   ${brl(taxas)}`);
  console.log(`Líquido: ${brl(soma - taxas)}\n`);
}

buscar().catch((e) => {
  console.error("Erro:", e.message);
  process.exit(1);
});
