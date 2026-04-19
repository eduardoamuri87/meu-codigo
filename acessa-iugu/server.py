#!/usr/bin/env python3
# Mini servidor local: serve o HTML e faz proxy para a API da Iugu.
# Uso: python3 server.py   →   abre http://localhost:8787

import base64
import mimetypes
import os
import re
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

AQUI = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "8787"))
HOST = os.environ.get("HOST", "127.0.0.1")
URL_PREFIX = os.environ.get("URL_PREFIX", "").rstrip("/")
AUTH_USER = os.environ.get("AUTH_USER", "")
AUTH_PASS = os.environ.get("AUTH_PASS", "")
EXIGE_AUTH = bool(AUTH_USER and AUTH_PASS)
CREDENCIAL_ESPERADA = (
    "Basic " + base64.b64encode(f"{AUTH_USER}:{AUTH_PASS}".encode()).decode()
    if EXIGE_AUTH else None
)

# Whitelist de endpoints de LEITURA permitidos. Qualquer caminho fora
# desta lista é bloqueado antes de sair pra Iugu, mesmo via GET.
ENDPOINTS_IUGU_PERMITIDOS = [
    re.compile(r"^v1/invoices/?$"),                                 # listar faturas
    re.compile(r"^v1/invoices/[A-Za-z0-9]+/?$"),                    # consultar fatura
    re.compile(r"^v1/customers/?$"),                                # listar clientes
    re.compile(r"^v1/customers/[A-Za-z0-9]+/?$"),                   # consultar cliente
    re.compile(r"^v1/subscriptions/?$"),                            # listar assinaturas
    re.compile(r"^v1/subscriptions/[A-Za-z0-9]+/?$"),               # consultar assinatura
    re.compile(r"^v1/plans/?$"),                                    # listar planos
    re.compile(r"^v1/plans/[A-Za-z0-9]+/?$"),                       # consultar plano
    re.compile(r"^v1/accounts/[A-Za-z0-9]+/?$"),                    # consultar conta
]

ENDPOINTS_STRIPE_PERMITIDOS = [
    re.compile(r"^v1/balance_transactions/?$"),                     # listar transações do saldo
    re.compile(r"^v1/balance_transactions/[A-Za-z0-9_]+/?$"),       # consultar transação do saldo
    re.compile(r"^v1/subscriptions/?$"),                            # listar assinaturas
    re.compile(r"^v1/subscriptions/[A-Za-z0-9_]+/?$"),              # consultar assinatura
    re.compile(r"^v1/customers/?$"),                                # listar clientes
    re.compile(r"^v1/customers/[A-Za-z0-9_]+/?$"),                  # consultar cliente
    re.compile(r"^v1/products/?$"),                                 # listar produtos
    re.compile(r"^v1/products/[A-Za-z0-9_]+/?$"),                   # consultar produto
    re.compile(r"^v1/prices/?$"),                                   # listar preços
    re.compile(r"^v1/prices/[A-Za-z0-9_]+/?$"),                     # consultar preço
    re.compile(r"^v1/invoices/?$"),                                 # listar faturas
    re.compile(r"^v1/invoices/[A-Za-z0-9_]+/?$"),                   # consultar fatura
    re.compile(r"^v1/charges/?$"),                                  # listar charges
    re.compile(r"^v1/charges/[A-Za-z0-9_]+/?$"),                    # consultar charge
    re.compile(r"^v1/payouts/?$"),                                  # listar payouts
    re.compile(r"^v1/payouts/[A-Za-z0-9_]+/?$"),                    # consultar payout
    re.compile(r"^v1/balance/?$"),                                  # consultar saldo
]


def endpoint_permitido(caminho_sem_query: str, lista) -> bool:
    return any(p.match(caminho_sem_query) for p in lista)

def ler_token(env_var: str, arquivo: str) -> str:
    valor = os.environ.get(env_var, "").strip()
    if valor:
        return valor
    caminho = os.path.join(AQUI, arquivo)
    if os.path.isfile(caminho):
        with open(caminho, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""


TOKEN_IUGU = ler_token("IUGU_TOKEN", "token.txt")
AUTH_IUGU = "Basic " + base64.b64encode((TOKEN_IUGU + ":").encode()).decode()

TOKEN_STRIPE = ler_token("STRIPE_TOKEN", "token-stripe.txt")
AUTH_STRIPE = "Bearer " + TOKEN_STRIPE


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("  ", fmt % args)

    def _proxy(self, resto, base_url, auth_header, whitelist, rotulo):
        so_caminho = resto.split("?")[0]
        if not endpoint_permitido(so_caminho, whitelist):
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'{"error":"endpoint nao permitido pela whitelist"}')
            print(f"   BLOQUEADO ({rotulo}): {so_caminho}")
            return
        destino = base_url + resto
        req = urllib.request.Request(destino, headers={"Authorization": auth_header})
        try:
            with urllib.request.urlopen(req) as resp:
                body = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as e:
            body = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def _autenticado(self) -> bool:
        if not EXIGE_AUTH:
            return True
        fornecido = self.headers.get("Authorization", "")
        return fornecido == CREDENCIAL_ESPERADA

    def _responder_401(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="relatorios"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("autenticacao necessaria".encode())

    def do_GET(self):
        if not self._autenticado():
            self._responder_401()
            return

        # Se o servidor está atrás de um reverse-proxy em subpath, tira o prefixo.
        if URL_PREFIX and self.path.startswith(URL_PREFIX):
            self.path = self.path[len(URL_PREFIX):] or "/"

        # Proxy: /api/iugu/<resto>  →  https://api.iugu.com/<resto>
        if self.path.startswith("/api/iugu/"):
            resto = self.path[len("/api/iugu/"):]
            self._proxy(resto, "https://api.iugu.com/", AUTH_IUGU, ENDPOINTS_IUGU_PERMITIDOS, "iugu")
            return

        # Proxy: /api/stripe/<resto>  →  https://api.stripe.com/<resto>
        if self.path.startswith("/api/stripe/"):
            resto = self.path[len("/api/stripe/"):]
            self._proxy(resto, "https://api.stripe.com/", AUTH_STRIPE, ENDPOINTS_STRIPE_PERMITIDOS, "stripe")
            return

        # Arquivos estáticos
        caminho = "/index-iugu.html" if self.path == "/" else self.path.split("?")[0]
        full = os.path.join(AQUI, caminho.lstrip("/"))
        if not os.path.isfile(full):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"nao encontrado")
            return
        mime, _ = mimetypes.guess_type(full)
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    modo_auth = "com Basic Auth" if EXIGE_AUTH else "SEM auth"
    print(f"\n  Servidor rodando em http://{HOST}:{PORT} ({modo_auth})\n")
    HTTPServer((HOST, PORT), Handler).serve_forever()
