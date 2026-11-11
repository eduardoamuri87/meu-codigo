# programas.amuri.com.br rodando local

Cópia do WordPress de produção no Mac (LocalWP), para criar e testar landing pages
sem mexer no site no ar.

## Como as LPs são feitas

Não é Elementor nem editor de blocos: cada LP é um **template PHP do tema `amuri`**.
O tema fica neste repositório, em [`amuri/tema`](../tema).

- DSM: `amuri/tema/page-lp-dsm.php` (página id 2967, URL `/dsm/`)
- Imagens: `amuri/tema/public/images/lp-dsm/`
- CSS: Tailwind compilado em `public/css/global.css`. Classes novas exigem rebuild do tema.

"Duplicar página" no painel copia só o conteúdo. Para uma LP nova é preciso um template novo.

## Refazer o ambiente

1. **Exportar** em produção: All-in-One WP Migration → Exportar → Arquivo. Baixe o `.wpress` (≈1,1 GB).
2. **Apagar o backup do servidor** (All-in-One → Backups), porque ele contém o banco inteiro (clientes, CPFs, chaves Iugu).
3. **Local**: o site `programas-amuri` já existe. Se for do zero: `brew install --cask local`
   e crie um site com esse nome ("Preferred"). Dê **Start site**.
4. **Importar**:
   ```bash
   cd amuri/wordpress-local
   ./importar.sh ~/Downloads/programas-amuri-com-br-AAAAMMDD-....wpress
   ```
   Isso **sobrescreve** banco, plugins e uploads do site local, e copia o tema de produção
   por cima de `amuri/tema`. O script recusa rodar se o tema tiver alterações sem commit.
   Depois, `git status amuri/tema` mostra o que foi mexido direto no servidor.
   Em Mac novo, o script também cria o link `wp-content/themes/amuri → amuri/tema`.
5. Abrir http://programas-amuri.local/dsm/. Painel em `/wp-admin` com o login de produção.

## O que o script faz e por quê

| Passo | Por quê |
|---|---|
| Extrai o `.wpress` com `wpress_extract.py` | O import do plugin gratuito trava com arquivo grande, e "Restaurar" também não funcionou |
| Ignora `wpvividbackups`, `litespeed`, `object-cache.php` | 500 MB de backup inútil, mais cache que só funciona no servidor |
| Importa o banco com `sql_mode=''` | O MySQL 8 do Local recusa datas `0000-00-00` que o MariaDB de produção aceita |
| Troca `SERVMASK_PREFIX_` → `wp_` | Placeholder do All-in-One para o prefixo das tabelas |
| `search-replace` da URL (normal e com `\/`) | Produção → `http://programas-amuri.local`, incluindo dados serializados e JSON |
| Reativa o tema `amuri` | O dump vem com `template` vazio |
| Define `AMBIENT_VAR_DEF = 'local'` no `wp-config.php` | O `header.php` do tema dá erro 500 sem ela. Em produção vale `'production'` e liga o Analytics |
| Ativa só plugins "inofensivos" | O dump vem com todos os plugins desativados |

**Ficam desligados de propósito**: Iugu, Stripe, WP Mail SMTP, PixelYourSite, Clarity,
Insert Headers and Footers, LiteSpeed, miniOrange MCP, WPvivid. Assim nada cobra
cliente, manda e-mail real ou dispara pixel a partir do Mac. E-mails do WordPress caem no
Mailpit do Local. O mu-plugin `amuri-iugu-split-juros` fica ativo, mas só age
quando a Iugu gera fatura.

## Editar o tema

O código está em `meu-codigo/amuri/tema`. No Local, `wp-content/themes/amuri` é um **link
simbólico** para essa pasta, então o que você salva no repositório aparece na hora no site local.

```bash
cd amuri/tema
npm install          # só na primeira vez (Node 25 funciona, o README do tema pede 18)
npm run dev          # watch do CSS + BrowserSync em http://localhost:3000 (recarrega ao salvar)
npm run build:css    # compila o CSS uma vez (o "gulp css" do README do tema não existe mais)
```

- Edite o CSS em `assets/css/`, nunca em `public/css/`, porque o build sobrescreve o `public/`.
- O commit `9398c62 estado de produção` é o tema como estava no servidor em 2026-11-11.
  Para saber quais arquivos subir: `git diff --stat 9398c62 HEAD -- amuri/tema`. Se houver um
  import mais novo, use o commit dele como base.
- O BrowserSync aponta para o site local via `gulp-config.json`, que fica fora do Git
  (o `.gitignore` do tema também ignora `node_modules`).
- Histórico: o `global.css` de produção tinha 4 ajustes que não estavam no fonte. Eles foram portados
  em 2026-11-11, então compilar a partir do fonte reproduz o CSS de produção.

## Criar uma LP nova

1. Copiar `page-lp-dsm.php` para `page-lp-<novo>.php` e trocar o `Template Name:` no topo.
2. Criar `public/images/lp-<novo>/` com os assets.
3. Trocar textos e o produto/link de compra (hoje leva ao `/carrinho/`).
4. No painel local: nova página, escolher o template, definir a URL e testar.
5. Produção: subir os arquivos novos do tema, criar a página e o produto no WooCommerce,
   e incluir o produto no split da Iugu se for o caso.

## Onde fica cada coisa

- Tema (código): `meu-codigo/amuri/tema`
- Site: `~/Local Sites/programas-amuri/app/public` (`wp-content/themes/amuri` é link para o tema)
- Backup da pasta do tema antes de virar link: `~/Local Sites/programas-amuri/tema-amuri-backup-20261111` (pode apagar)
- Config PHP/nginx do site: `~/Local Sites/programas-amuri/conf/` (limites de upload já subidos para 2 GB, `.bak` com os originais)
- Log de erros PHP: `~/Local Sites/programas-amuri/logs/php/error.log`
