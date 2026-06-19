<?php
/**
 * Cria um PaymentIntent na Stripe e devolve o client_secret para o front-end.
 *
 * O front-end (checkout-livro.html) chama este endpoint, recebe o client_secret
 * e a chave publicável, e monta o Payment Element. O VALOR é definido aqui no
 * servidor a partir do id do produto — nunca confiamos no valor enviado pelo cliente.
 */

header('Content-Type: application/json');

// GET: devolve apenas a chave publicável (segura para o front-end). Usada no
// modo de criação adiada do PaymentIntent, em que os elementos são montados
// antes de existir um PaymentIntent.
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

// --- Catálogo: a fonte da verdade do preço fica no servidor ---
// Valores em centavos. Mantenha em sincronia com o resumo exibido no checkout.
$PRODUTOS = [
    '1' => ['amount' => 8900,  'descricao' => 'Dinheiro Sem Medo — 1 exemplar'],
    '2' => ['amount' => 14400, 'descricao' => 'Dinheiro Sem Medo — 2 exemplares'],
];

/**
 * Valida um CPF (dígitos verificadores). Aceita com ou sem formatação.
 */
function cpfValido($cpf) {
    $cpf = preg_replace('/\D/', '', (string)$cpf);
    if (strlen($cpf) !== 11 || preg_match('/^(\d)\1{10}$/', $cpf)) {
        return false;
    }
    for ($t = 9; $t < 11; $t++) {
        $soma = 0;
        for ($i = 0; $i < $t; $i++) {
            $soma += (int)$cpf[$i] * (($t + 1) - $i);
        }
        $digito = ((10 * $soma) % 11) % 10;
        if ((int)$cpf[$t] !== $digito) {
            return false;
        }
    }
    return true;
}

try {
    $config = require __DIR__ . '/config.php';
    $secretKey = $config['secret_key'] ?? null;
    $publishableKey = $config['publishable_key'] ?? null;

    if (!$secretKey || !$publishableKey) {
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

    // CPF é obrigatório (revalidado aqui, não confiamos só no front-end).
    $cpf = preg_replace('/\D/', '', (string)($input['cpf'] ?? ''));
    if (!cpfValido($cpf)) {
        http_response_code(400);
        echo json_encode(['error' => 'CPF inválido']);
        exit;
    }

    // Metadata: produto/cpf/origem + parâmetros de rastreio (UTM etc.) vindos da URL.
    $metadata = [
        'produto' => $produtoId,
        'cpf'     => $cpf,
        'origem'  => 'site-livro',
    ];
    $tracking = $input['tracking'] ?? [];
    if (is_array($tracking)) {
        $n = 0;
        foreach ($tracking as $chave => $valor) {
            if ($n >= 20) break; // trava de segurança (Stripe permite até 50 chaves)
            $chave = substr(preg_replace('/[^a-zA-Z0-9_]/', '', (string)$chave), 0, 40);
            if ($chave === '' || isset($metadata[$chave])) continue;
            $metadata[$chave] = substr((string)$valor, 0, 500);
            $n++;
        }
    }

    // Parâmetros do PaymentIntent. automatic_payment_methods deixa a Stripe
    // oferecer todos os métodos habilitados no Dashboard (cartão, Pix, etc.).
    $params = [
        'amount'      => $produto['amount'],
        'currency'    => 'brl',
        'description' => $produto['descricao'],
        'automatic_payment_methods' => ['enabled' => 'true'],
        'metadata'    => $metadata,
    ];

    $ch = curl_init('https://api.stripe.com/v1/payment_intents');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERPWD        => $secretKey . ':', // Basic auth: chave secreta como usuário
        CURLOPT_POSTFIELDS     => http_build_query($params),
        CURLOPT_TIMEOUT        => 30,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);

    if ($curlError) {
        throw new Exception("Erro de conexão com a Stripe: $curlError");
    }

    $data = json_decode($response, true);

    if ($httpCode >= 400 || !isset($data['client_secret'])) {
        $msg = $data['error']['message'] ?? 'Não foi possível iniciar o pagamento.';
        throw new Exception($msg);
    }

    echo json_encode([
        'clientSecret'   => $data['client_secret'],
        'publishableKey' => $publishableKey,
        'amount'         => $produto['amount'],
        'descricao'      => $produto['descricao'],
    ]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
