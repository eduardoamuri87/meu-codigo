<?php
/**
 * Cria uma Checkout Session no modo EMBEDDED e devolve o client_secret.
 *
 * Diferente de criar-pagamento.php (Payment Element), aqui usamos o Checkout
 * do Stripe — o único caminho em que o PIX aparece inline para esta conta
 * (o Payment Element filtra o PIX; ver investigação de 2026-06-25).
 *
 * GET  → devolve a chave publicável (para o Stripe.js no front).
 * POST → cria a sessão para o produto informado e devolve o clientSecret.
 *        O VALOR é definido aqui no servidor a partir do id do produto.
 */

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $config = require __DIR__ . '/config.php';
    echo json_encode(['publishableKey' => $config['publishable_key'] ?? '']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Método não permitido']);
    exit;
}

// Catálogo: fonte da verdade do preço fica no servidor (centavos).
$PRODUTOS = [
    '1' => ['amount' => 8900,  'descricao' => 'Dinheiro Sem Medo — 1 exemplar'],
    '2' => ['amount' => 14400, 'descricao' => 'Dinheiro Sem Medo — 2 exemplares'],
];

try {
    $config = require __DIR__ . '/config.php';
    $secretKey = $config['secret_key'] ?? null;
    if (!$secretKey) {
        throw new Exception('Configuração da Stripe ausente.');
    }

    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $produtoId = (string)($input['produto'] ?? '1');
    if (!isset($PRODUTOS[$produtoId])) {
        http_response_code(400);
        echo json_encode(['error' => 'Produto inválido']);
        exit;
    }
    $produto = $PRODUTOS[$produtoId];

    // Metadata: produto/origem + parâmetros de rastreio (UTM etc.) vindos da URL.
    $metadata = ['produto' => $produtoId, 'origem' => 'site-livro-embed'];
    $tracking = $input['tracking'] ?? [];
    if (is_array($tracking)) {
        $n = 0;
        foreach ($tracking as $chave => $valor) {
            if ($n >= 20) break;
            $chave = substr(preg_replace('/[^a-zA-Z0-9_]/', '', (string)$chave), 0, 40);
            if ($chave === '' || isset($metadata[$chave])) continue;
            $metadata[$chave] = substr((string)$valor, 0, 500);
            $n++;
        }
    }

    $params = [
        'ui_mode' => 'embedded',
        'mode'    => 'payment',
        'line_items' => [[
            'price_data' => [
                'currency'     => 'brl',
                'product_data' => ['name' => $produto['descricao']],
                'unit_amount'  => $produto['amount'],
            ],
            'quantity' => 1,
        ]],
        // Cartão + Pix explícitos. No Checkout o Pix é elegível (ao contrário
        // do Payment Element). Pix coleta o CPF do pagador automaticamente.
        'payment_method_types' => ['card', 'pix'],
        // Livro físico: coleta endereço de entrega no Brasil.
        'shipping_address_collection' => ['allowed_countries' => ['BR']],
        // Coleta o CPF/CNPJ (fiscal) também no fluxo de cartão.
        'tax_id_collection' => ['enabled' => 'true'],
        'metadata' => $metadata,
        // Propaga metadata ao PaymentIntent (webhook.php lê do PI).
        'payment_intent_data' => ['metadata' => $metadata],
    ];

    // return_url: repassa os MESMOS parâmetros de rastreio (UTM, fbclid, gclid…)
    // adiante, para não perder a origem do lead na página de sucesso. O
    // {CHECKOUT_SESSION_ID} precisa ficar LITERAL (não url-encoded), por isso
    // montamos o corpo à mão preservando as chaves.
    $forward = array_diff_key($metadata, array_flip(['produto', 'origem']));
    $query   = http_build_query($forward);
    $returnUrl = 'https://programas.amuri.com.br/deu-certo.html?'
               . ($query !== '' ? $query . '&' : '')
               . 'session_id={CHECKOUT_SESSION_ID}';
    $body  = http_build_query($params);
    $body .= '&return_url=' . str_replace(['%7B', '%7D'], ['{', '}'], rawurlencode($returnUrl));

    $ch = curl_init('https://api.stripe.com/v1/checkout/sessions');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERPWD        => $secretKey . ':',
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_TIMEOUT        => 30,
    ]);

    $response  = curl_exec($ch);
    $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    if ($curlError) {
        throw new Exception("Erro de conexão com a Stripe: $curlError");
    }

    $data = json_decode($response, true);
    if ($httpCode >= 400 || !isset($data['client_secret'])) {
        throw new Exception($data['error']['message'] ?? 'Não foi possível iniciar o checkout.');
    }

    echo json_encode(['clientSecret' => $data['client_secret']]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
