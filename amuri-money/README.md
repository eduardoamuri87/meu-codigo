# Amuri Money

Sistema interno simples de controle de contas a pagar e a receber da Amuri Consult.

## Stack

- Next.js 16 (App Router, TypeScript)
- Tailwind CSS v4 + shadcn/ui
- Drizzle ORM + Turso (SQLite na nuvem)
- Auth com Lucia (a ser adicionado no Prompt 3)

## Rodando localmente

### 1. Instalar dependências

```bash
npm install
```

### 2. Configurar o banco Turso

**Opção A — Turso (recomendado):**

```bash
# Instalar o CLI do Turso
curl -sSfL https://get.tur.so/install.sh | bash

# Login e criação do banco
turso auth login
turso db create amuri-money

# Pegar as credenciais
turso db show amuri-money --url
turso db tokens create amuri-money
```

**Opção B — SQLite local** (sem Turso, para dev rápido):

Use `DATABASE_URL=file:./local.db` no `.env` e deixe `DATABASE_AUTH_TOKEN` vazio.

### 3. Variáveis de ambiente

Copie o exemplo e preencha:

```bash
cp .env.example .env
```

- `DATABASE_URL` — URL retornada pelo Turso (ou `file:./local.db`).
- `DATABASE_AUTH_TOKEN` — token do Turso (vazio para SQLite local).
- `AUTH_SECRET` — gere com `openssl rand -base64 32`.

### 4. Criar as tabelas

```bash
npm run db:push
```

### 5. Rodar o servidor

```bash
npm run dev
```

Acesse [http://localhost:3000](http://localhost:3000).

## Scripts

- `npm run dev` — servidor de desenvolvimento
- `npm run build` — build de produção
- `npm run start` — servidor de produção
- `npm run lint` — ESLint
- `npm run db:push` — aplica o schema no banco (sem migração)
- `npm run db:studio` — abre o Drizzle Studio

## Estrutura

```
app/                 # Rotas (App Router)
components/ui/       # Componentes shadcn/ui
lib/db/              # Schema e client do Drizzle
lib/auth/            # Autenticação (Lucia)
drizzle/             # Migrações geradas
```

## Deploy

Deploy planejado para Vercel + Turso (ver Prompt 9 do plano).
