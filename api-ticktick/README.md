# Eleonora — MCP do TickTick

MCP server remoto que fala com a **API v2 interna** do TickTick (não a
pública/OAuth), pra conseguir filtrar tarefas por `assignee` — coisa que o
connector oficial e a API pública não expõem.

Destino: rodar no Fly.io e ser consumido como **Custom Connector** no Claude
(desktop, web e mobile via Projects).

## Arquivos

- [discover_user_id.py](discover_user_id.py) — script local que usamos uma vez para descobrir o userId interno
- [ticktick_client.py](ticktick_client.py) — cliente HTTP da API v2
- [server.py](server.py) — MCP server (stdio local ou HTTP remoto)
- [Dockerfile](Dockerfile) + [fly.toml](fly.toml) — deploy

## Tools expostas

- `list_my_tasks(include_unassigned=False)` — filtra por `assignee = seu userId`
- `list_projects()` — lista + inbox
- `list_project_tasks(project_id)` — tarefas abertas de um projeto
- `search_tasks(query, limit=30)` — busca por texto
- `create_task(title, project_id?, content, priority, due_date?)`
- `complete_task(task_id)`
- `update_task(task_id, title?, content?, priority?, due_date?, project_id?)`

## Setup (próximos passos)

### 1. Dependências locais

```bash
cd api-ticktick
source .venv/bin/activate
pip install -r requirements.txt
```

FastMCP exige Python 3.10+. A `.venv` atual está no 3.9 — recriar com Python novo:

```bash
brew install python@3.12
deactivate
rm -rf .venv
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Env vars

Edite `.env` e preencha:
- `TICKTICK_EMAIL`, `TICKTICK_PASSWORD` — já estão
- `TICKTICK_USER_ID=120203111`
- `MCP_TOKEN` — gere com:
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```

### 3. Testar local (HTTP)

```bash
python server.py http
```

Em outro terminal:

```bash
curl -s http://localhost:8000/$MCP_TOKEN/mcp
```

Deve retornar algo MCP-ish (não 404).

### 4. Deploy no Fly.io

```bash
# 1. instalar flyctl
brew install flyctl
fly auth signup   # ou `fly auth login` se já tem conta

# 2. criar app
cd api-ticktick
fly launch --no-deploy --copy-config --name eleonora-ticktick --region gru
# responda N para banco de dados, Y/N para tudo mais conforme preferir

# 3. setar secrets
fly secrets set \
  TICKTICK_EMAIL="..." \
  TICKTICK_PASSWORD="..." \
  TICKTICK_USER_ID="120203111" \
  MCP_TOKEN="..."

# 4. deploy
fly deploy
```

Ao final, a URL do connector será:
```
https://eleonora-ticktick.fly.dev/<MCP_TOKEN>/mcp
```

### 5. Custom Connector no Claude

No Claude (claude.ai):
1. Settings → Connectors → Custom Connector
2. URL: a do Fly acima (path com o MCP_TOKEN dentro)
3. Nomeie como "Eleonora / TickTick"
4. Ativa no Project da Eleonora

## Riscos e limitações

- **API não oficial**: pode quebrar se o TickTick mudar algo no endpoint v2.
  Se as tools pararem de funcionar, voltamos aqui para ajustar headers/formato.
- **Path secreto ≠ bearer auth**: quem descobrir a URL completa consegue operar.
  Segurança decente pra uso pessoal; se quisermos fortalecer, adicionamos
  `Authorization: Bearer` via middleware Starlette.
- **Token de sessão expira**: o cliente re-loga automaticamente em 401/403.
  Se a senha mudar, atualizar no `fly secrets set`.
