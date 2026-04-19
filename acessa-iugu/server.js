// Mini servidor local: serve o HTML e faz proxy para a API da Iugu.
// Uso: node server.js   →   abre http://localhost:8787

import { createServer } from "node:http";
import { readFile, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, extname } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TOKEN = readFileSync(join(__dirname, "token.txt"), "utf8").trim();
const AUTH = "Basic " + Buffer.from(TOKEN + ":").toString("base64");
const PORT = 8787;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const server = createServer(async (req, res) => {
  // Proxy: tudo em /api/iugu/* vai pra https://api.iugu.com/*
  if (req.url.startsWith("/api/iugu/")) {
    const path = req.url.replace("/api/iugu/", "");
    const url = `https://api.iugu.com/${path}`;
    try {
      const resp = await fetch(url, { headers: { Authorization: AUTH } });
      const body = await resp.text();
      res.writeHead(resp.status, { "Content-Type": "application/json; charset=utf-8" });
      res.end(body);
    } catch (e) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // Arquivos estáticos
  let file = req.url === "/" ? "/index-iugu.html" : req.url;
  file = file.split("?")[0];
  const full = join(__dirname, file);
  readFile(full, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("não encontrado");
      return;
    }
    res.writeHead(200, { "Content-Type": MIME[extname(full)] || "application/octet-stream" });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`\n  Iugu local rodando em: http://localhost:${PORT}\n`);
});
