# Como Configurar o Google Sheets para Receber as Avaliações

## Passo 1: Criar a Planilha

1. Acesse [Google Sheets](https://sheets.google.com)
2. Crie uma nova planilha
3. Na primeira linha, adicione os cabeçalhos:
   - A1: `Data`
   - B1: `Nome`
   - C1: `E-mail`
   - D1: `Nota`
   - E1: `Depoimento`
   - F1: `Destaque`

**Importante**: A coluna "Destaque" serve para marcar depoimentos que aparecerão em destaque na página de depoimentos. Coloque um asterisco `*` nesta coluna para os depoimentos que você quer destacar.

## Passo 2: Criar o Script

1. No menu, clique em **Extensões** → **Apps Script**
2. Delete todo o código existente
3. Cole o código abaixo:

```javascript
// Recebe novos depoimentos (POST)
function doPost(e) {
  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
    const data = JSON.parse(e.postData.contents);

    sheet.appendRow([
      data.date,
      data.name,
      data.email,
      data.rating,
      data.testimonial,
      '' // coluna destaque (vazia por padrão)
    ]);

    return ContentService
      .createTextOutput(JSON.stringify({ success: true }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService
      .createTextOutput(JSON.stringify({ success: false, error: error.message }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

// Retorna todos os depoimentos (GET)
function doGet(e) {
  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
    const data = sheet.getDataRange().getValues();

    // Pula o cabeçalho (primeira linha)
    const depoimentos = [];
    for (let i = 1; i < data.length; i++) {
      const row = data[i];
      // Só adiciona se tiver nome e depoimento
      if (row[1] && row[4]) {
        depoimentos.push({
          date: row[0],
          name: row[1],
          email: row[2],
          rating: row[3],
          testimonial: row[4],
          destaque: row[5] || ''
        });
      }
    }

    return ContentService
      .createTextOutput(JSON.stringify(depoimentos))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService
      .createTextOutput(JSON.stringify({ error: error.message }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}
```

4. Salve o projeto (Ctrl+S ou Cmd+S)
5. Dê um nome ao projeto, como "Avaliações Livro"

## Passo 3: Publicar como Web App

1. Clique em **Implantar** → **Nova implantação**
2. Clique no ícone de engrenagem ao lado de "Selecionar tipo"
3. Selecione **App da Web**
4. Configure:
   - **Descrição**: Receber e exibir avaliações do livro
   - **Executar como**: Eu mesmo
   - **Quem pode acessar**: Qualquer pessoa
5. Clique em **Implantar**
6. Autorize o app (vai pedir permissões)
7. **COPIE A URL** que aparecer (algo como `https://script.google.com/macros/s/xxx/exec`)

## Passo 4: Adicionar a URL nos arquivos HTML

1. Abra o arquivo `index.html`
2. Encontre a linha:
   ```javascript
   const GOOGLE_SCRIPT_URL = 'COLE_AQUI_A_URL_DO_SEU_GOOGLE_SCRIPT';
   ```
3. Substitua pela URL que você copiou

4. Abra o arquivo `depoimentos.html`
5. Encontre a mesma linha e substitua pela mesma URL

## Pronto!

Agora você tem duas páginas funcionando:
- **index.html**: Formulário para coletar depoimentos
- **depoimentos.html**: Página que exibe todos os depoimentos

### Como marcar depoimentos em destaque

1. Abra a planilha do Google Sheets
2. Na coluna "Destaque" (coluna F), coloque um asterisco `*` nos depoimentos que você quer destacar
3. Os depoimentos marcados aparecerão em destaque no topo da página de depoimentos

---

## Dica Extra: Notificação por Email

Se quiser receber um email quando alguém avaliar, substitua a função `doPost` por esta versão:

```javascript
function doPost(e) {
  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
    const data = JSON.parse(e.postData.contents);

    sheet.appendRow([
      data.date,
      data.name,
      data.email,
      data.rating,
      data.testimonial,
      ''
    ]);

    // Envia email de notificação
    const estrelas = '★'.repeat(data.rating) + '☆'.repeat(5 - data.rating);
    MailApp.sendEmail({
      to: 'SEU_EMAIL@gmail.com',
      subject: `Nova Avaliação: ${estrelas}`,
      body: `Nome: ${data.name}\nE-mail: ${data.email}\nNota: ${data.rating}/5\n\nDepoimento:\n${data.testimonial}`
    });

    return ContentService
      .createTextOutput(JSON.stringify({ success: true }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService
      .createTextOutput(JSON.stringify({ success: false, error: error.message }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}
```

Lembre-se de substituir `SEU_EMAIL@gmail.com` pelo seu email real.

---

## Atualizando o Script

Se você já tinha o script publicado e precisa atualizar:

1. Vá em **Implantar** → **Gerenciar implantações**
2. Clique no ícone de lápis (editar)
3. Em "Versão", selecione **Nova versão**
4. Clique em **Implantar**

A URL permanece a mesma, mas agora com o código atualizado.
