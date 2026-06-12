# artigo julio — Observatório Briefing 04

Briefing visual em HTML/CSS sobre o artigo **"From Order to Chaos: How Consumers Lose Control of Risks (and of Themselves)"** (Julio C. Leandro & Delane Botelho, 2025).

Este documento descreve como o projeto está organizado para facilitar edições futuras (inclusive via Claude Code).

---

## Visão geral

Não há build, framework ou dependências de npm. É HTML estático + CSS + um web component em JS puro. Para visualizar, basta abrir o arquivo HTML no navegador (ou rodar um servidor estático local: `python3 -m http.server`).

Os arquivos foram pensados para edição direta no VS Code — o HTML é canônico (tags fechadas, atributos com aspas) e o CSS é organizado por seções comentadas.

---

## Estrutura de pastas

```
.
├── Briefing 04.html              ← ARQUIVO PRINCIPAL (versão atual em uso)
├── Briefing 04 v2.html           ← snapshot de uma versão anterior
├── Briefing 04 - standalone.html ← bundle self-contained (offline / compartilhamento)
├── Briefing 04-print.html        ← versão otimizada para impressão / PDF
├── briefing-v2.css               ← stylesheet legado (NÃO é usado pelo Briefing 04.html)
├── image-slot.js                 ← web component <image-slot> (drag-and-drop de imagens)
├── .image-slots.state.json       ← estado persistente das imagens arrastadas
├── assets/                       ← PDFs e imagens finais usadas no briefing
│   ├── from-order-to-chaos.pdf
│   ├── consumer-over-indebtedness.pdf
│   └── vivian.png
└── uploads/                      ← materiais brutos enviados pelo usuário (referência)
    ├── *.pdf                     ← artigos de origem
    ├── *.png                     ← screenshots, sketches, fotos
    └── *.html / *.docx           ← versões anteriores / template original
```

---

## Arquivo principal: `Briefing 04.html`

É um **único arquivo monolítico** (~3.800 linhas) que contém:

1. `<head>` — fontes Google (Playfair Display + Space Mono), thumbnail de bundler.
2. `<style>` interno — TODO o CSS do briefing vive aqui (não em `briefing-v2.css`).
3. `<body>` — seções HTML em ordem narrativa.
4. `<script>` final — micro-interações (scroll progress, reveal-on-scroll, tweaks panel).
5. `<style id="__om-edit-overrides">` — regras `!important` geradas por edições diretas no editor visual. **Ao mudar elementos referenciados aqui, edite ou remova a regra correspondente** — senão o `!important` sobrescreve.

### Variáveis CSS (`:root`)

Tokens centrais no topo do `<style>`:

```css
--bone, --forest, --clay, --rust, --moss, --ox  /* paleta */
--font-display, --font-mono                      /* tipografia */
--max-w: 1200px    /* largura máxima do container .wrap */
--col-w: 850px     /* largura das colunas de texto (.col, p.body, etc.) */
```

Para alterar a largura das colunas de texto **globalmente**, mude `--col-w`. Atenção: alguns parágrafos têm `width` inline (resultado de edições diretas anteriores) que sobrescreve a variável — busque por `style="width:` se um trecho específico não responder.

### Seções (na ordem em que aparecem)

| Id da `<section>` | Conteúdo |
|---|---|
| `top` | Hero / capa com título e metadados |
| `ponte-abertura` | Observatório como ponte (intro) |
| `abertura` | 01 · Abertura — quote + intro do artigo |
| `conceito` | 02 · Conceito central |
| `comentario-vivian-trajetoria` | Comentário externo da Vívian (antes da trajetória) |
| `trajetoria` | 04 · Trajetória — chart Ordem → Caos |
| `comentario-vivian` | Comentário externo da Vívian (antes dos fatores) |
| `forcas` | 05 · Quatro fatores agravantes |
| `dimensoes` | 06 · Quatro dimensões do caos (voice cards) |
| `responsabilizacao` | 07 · Limites da responsabilização (seção rust) |
| `recomendacoes` | 08 · Seis intervenções recomendadas |
| `comentario-vivian-recomendacoes` | Comentário externo da Vívian (depois) |
| `fechamento` | Fechamento (seção rust escura) |
| `pesquisador` | Bio do pesquisador Julio Leandro (seção moss) |
| `entrevista` | Q&A em formato magazine |
| `links` | Links importantes / artigos relacionados |
| `proximo-passo` | Contato / próximo passo |

### Classes utilitárias importantes

- `.wrap` — container 1200px centralizado, padding lateral.
- `.col` — coluna de texto (`max-width: var(--col-w)`).
- `.section-bone` / `.section-rust` / `.section-forest` / `.section-moss` / `.section-ox` — variações de fundo / cor de texto.
- `.body` — parágrafo padrão (com `max-width: var(--col-w)`).
- `.section-tag` — eyebrow numerado (ex: "01 · Abertura").
- `.section-title` — título principal de cada seção.
- `.section-intro` — parágrafo introdutório (logo após o título).
- `blockquote.pull` — citação destacada com borda colorida.
- `.guest-note` — card de comentário externo (Vívian).
- `.voice-card` — card colorido das "dimensões do caos".

---

## Outros arquivos HTML

- **`Briefing 04 - standalone.html`** — versão "bundled" gerada por uma ferramenta de inline (todo CSS/JS/imagens embutidos como base64). Útil para enviar por e-mail ou hospedar em qualquer lugar sem precisar de pasta de assets. **Não edite este arquivo diretamente** — regere a partir do `Briefing 04.html`.
- **`Briefing 04-print.html`** — variação com regras `@media print` e ajustes de quebra de página, para gerar PDF via `Cmd/Ctrl + P`.
- **`Briefing 04 v2.html`** — snapshot histórico. Mantido como backup; pode ser deletado.

## `image-slot.js`

Define `<image-slot id="..." placeholder="..." shape="rect|rounded|circle|pill">`. Cada slot:

- aceita drop de imagem do desktop;
- persiste a imagem no `localStorage` do navegador associado ao `id`;
- também escreve em `.image-slots.state.json` quando rodando no ambiente original.

Para incorporar uma imagem definitiva (em vez de depender de drop), substitua o `<image-slot>` por `<img src="assets/...">`.

## `briefing-v2.css`

⚠️ **Legado.** O `Briefing 04.html` **não** referencia este arquivo (todo o CSS dele está inline). Mantido apenas por histórico. Pode ser deletado se quiser limpar.

---

## Convenções de edição

- **HTML canônico**: tags sempre fechadas, atributos com aspas duplas. Mantenha esse estilo para o arquivo continuar editável visualmente.
- **Atributos `data-comment-anchor`**: se aparecerem em algum elemento, preserve-os ao reestruturar — eles ancoram comentários de revisão.
- **`<style id="__om-edit-overrides">`** no final do arquivo: regras com `!important` geradas por edições visuais anteriores. Se uma edição não estiver "pegando", procure aqui antes.
- **Comente as seções**: o HTML usa marcadores `<!-- === SECTION NN — NOME === -->` para facilitar navegação no editor.
- **Não duplique arquivos para criar variantes** — prefira tweaks/variáveis no mesmo arquivo.

---

## Tipografia

- **Playfair Display** (display) — usada em títulos e citações.
- **Space Mono** (mono) — usada em eyebrows, números, metadados e alguns títulos.

Carregadas via Google Fonts no `<head>`. Para offline, baixe os `.woff2` e referencie via `@font-face`.

---

## Paleta

| Token | Hex aprox. | Uso |
|---|---|---|
| `--bone` | `#EEE6D6` | fundo claro padrão |
| `--forest` | `#1A2419` | texto principal, fundo escuro |
| `--clay` | `#D96B3D` | acentos quentes |
| `--rust` | `#8A2E1D` | seções de destaque (responsabilização, fechamento) |
| `--moss` | `#65725A` | seções verdes (ponte, pesquisador) |
| `--ox` | (oxblood) | acento secundário |

(Valores exatos no `:root` do `Briefing 04.html`.)

---

## Como continuar com Claude Code

Sugestões de prompts úteis:

- *"Procure todos os parágrafos com `width:` inline em `Briefing 04.html` e remova-os para que herdem `--col-w`."*
- *"Adicione uma nova seção entre `forcas` e `dimensoes` chamada `interludio`, no padrão visual de `.section-bone`."*
- *"Extraia o CSS inline de `Briefing 04.html` para `briefing.css` e referencie via `<link>`."*
- *"Gere uma versão `Briefing 04-mobile.html` com tweaks específicos para telas < 540px."*

Bom trabalho! 🌿
